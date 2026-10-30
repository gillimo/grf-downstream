"""Real temporary-project journeys; no private service or credentials required."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

import grf_starter as starter
from grf_client import Denied


class StarterTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / 'sample'
        starter.init(self.root, 'Build a project with measurable acceptance')

    def sign_in(self):
        return starter.lifecycle(self.root, 'sign-in', task='Implement and verify a real output')

    def passing(self):
        (self.root / 'checks/acceptance.py').write_text(
            'from pathlib import Path\nassert Path("result.txt").read_text() == "verified"\n')
        (self.root / 'result.txt').write_text('verified')

    def edit(self, operation):
        doc = starter.project(self.root)
        operation(doc)
        (self.root / 'project.grf').write_text(starter.HEADER + json.dumps(doc) + '\n```\n')

    def cli(self, *argv):
        return subprocess.run([sys.executable, str(self.root / 'grf.py'), *argv],
                              cwd=self.root, capture_output=True, text=True, timeout=20)

    def test_initial_acceptance_actually_fails_and_counts(self):
        self.sign_in()
        result = starter.run_checks(self.root)
        self.assertEqual((result['result'], result['executed']), ('FAIL', 1))
        receipt = json.loads((self.root / result['receipt']).read_text())
        self.assertEqual(receipt['checks'][0]['exit_code'], 1)
        self.assertIn('not been implemented', receipt['checks'][0]['stderr'])

    def test_real_cli_complete_journey(self):
        self.assertEqual(self.cli('session', 'sign-in', '--task', 'Verify generated project behavior').returncode, 0)
        self.assertNotEqual(self.cli('check').returncode, 0)
        self.passing()
        for argv in [('check',), ('session', 'complete', '--evidence', 'result.txt',
                                   '--summary', 'Verified expected result through real assertions'),
                     ('session', 'sign-out')]:
            result = self.cli(*argv)
            self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(starter.state(self.root)['status'], 'signed-out')
        self.assertEqual(len(list((self.root / '.grf/receipts').glob('*.json'))), 4)

    def test_resume_preserves_task_identity(self):
        original = self.sign_in()
        with self.assertRaises(ValueError):
            self.sign_in()
        resumed = starter.lifecycle(self.root, 'resume')
        for key in ('id', 'task', 'acceptance_ids', 'started_at'):
            self.assertEqual(original[key], resumed[key])

    def test_no_early_signout_or_false_completion(self):
        self.sign_in()
        (self.root / 'result.txt').write_text('evidence')
        with self.assertRaises(ValueError):
            starter.lifecycle(self.root, 'sign-out')
        with self.assertRaises(ValueError):
            starter.lifecycle(self.root, 'complete', evidence=['result.txt'], summary='Meaningful completion claim')
        self.assertIsNone(starter.state(self.root)['completion'])

    def test_changed_evidence_blocks_signout(self):
        self.sign_in()
        self.passing()
        starter.lifecycle(self.root, 'complete', evidence=['result.txt'], summary='Verified the output artifact')
        (self.root / 'result.txt').write_text('changed')
        with self.assertRaisesRegex(ValueError, 'evidence changed'):
            starter.lifecycle(self.root, 'sign-out')

    def test_fresh_failure_blocks_signout(self):
        self.sign_in()
        self.passing()
        starter.lifecycle(self.root, 'complete', evidence=['result.txt'], summary='Verified the output artifact')
        (self.root / 'checks/acceptance.py').write_text('raise SystemExit(12)\n')
        with self.assertRaisesRegex(ValueError, 'Fresh acceptance failed'):
            starter.lifecycle(self.root, 'sign-out')

    def test_existing_directory_never_overwritten(self):
        before = starter.sha(self.root / 'project.grf')
        with self.assertRaises(FileExistsError):
            starter.init(self.root, 'A different purpose')
        self.assertEqual(before, starter.sha(self.root / 'project.grf'))

    def test_empty_duplicate_and_removed_acceptance_fail(self):
        for checks in ([], [{'id': 'REG-OTHER', 'argv': ['x'], 'timeout_seconds': 1}],
                       [{'id': starter.REQUIRED, 'argv': ['x'], 'timeout_seconds': 1}] * 2):
            # Restore a known envelope for each independent invalid fixture.
            doc = {'format': 'grf.downstream-project/v1', 'checks': checks,
                   'admission': {'mode': 'local'}}
            (self.root / 'project.grf').write_text(starter.HEADER + json.dumps(doc) + '\n```\n')
            with self.assertRaises(ValueError):
                starter.project(self.root)

    def test_missing_executable_and_timeout_are_counted_failures(self):
        self.sign_in()
        self.edit(lambda doc: doc.update(checks=[
            {'id': starter.REQUIRED, 'argv': ['nonexistent-grf-executable-72913'], 'timeout_seconds': 1},
            {'id': 'REG-TIMEOUT', 'argv': ['{python}', '-c', 'import time; time.sleep(10)'], 'timeout_seconds': 1}]))
        result = starter.run_checks(self.root)
        self.assertEqual((result['executed'], result['passed']), (2, 0))

    def test_empty_and_comment_only_check_cannot_pass(self):
        self.sign_in()
        for text in ('', '# nothing\n', '"""Only documentation"""\npass\n'):
            (self.root / 'checks/acceptance.py').write_text(text)
            self.assertEqual(starter.run_checks(self.root)['result'], 'FAIL')

    def test_contract_mutation_during_checks_fails(self):
        self.sign_in()
        (self.root / 'checks/acceptance.py').write_text(
            'from pathlib import Path\np=Path("project.grf")\np.write_text(p.read_text()+"\\n")\n')
        self.assertEqual(starter.run_checks(self.root)['result'], 'FAIL')

    def test_remote_denial_never_launches(self):
        self.sign_in()
        self.edit(lambda doc: doc.update(admission={'mode': 'remote', 'enrollment': 'credentials/enrollment.json'}))
        with patch.object(starter, 'load_config', return_value={}), patch.object(starter, 'Client') as client, \
                patch.object(starter.subprocess, 'run') as launch:
            client.return_value.admit.side_effect = Denied()
            self.assertEqual(starter.run_checks(self.root)['result'], 'FAIL')
            launch.assert_not_called()

    def test_remote_missing_credentials_has_no_local_fallback(self):
        self.sign_in()
        self.edit(lambda doc: doc.update(admission={'mode': 'remote', 'enrollment': 'credentials/missing.json'}))
        with patch.object(starter.subprocess, 'run') as launch:
            self.assertEqual(starter.run_checks(self.root)['result'], 'FAIL')
            launch.assert_not_called()

    def test_lock_refuses_concurrent_writer(self):
        with starter.locked(self.root):
            with self.assertRaises(FileExistsError):
                with starter.locked(self.root):
                    self.fail('Second writer entered')

    def test_pinned_runtime_mutation_blocks_cli(self):
        with (self.root / '.grf-runtime/grf_starter.py').open('a') as stream:
            stream.write('\n# changed\n')
        result = self.cli('session', 'status')
        self.assertNotEqual(result.returncode, 0)
        self.assertIn('Runtime changed', result.stderr)

    def test_evidence_escape_rejected(self):
        self.sign_in()
        outside = Path(self.temp.name) / 'outside.txt'
        outside.write_text('outside')
        with self.assertRaisesRegex(ValueError, 'inside the project'):
            starter.lifecycle(self.root, 'complete', evidence=['../outside.txt'], summary='Cannot use external evidence')


if __name__ == '__main__':
    unittest.main()

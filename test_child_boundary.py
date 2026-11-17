"""Actual launch/cleanup regressions for the owner's child-process follow-up."""
import os
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import Mock, patch

import grf_process as managed
import grf_client as client
import grf_starter as starter
from test_process import alive


class ChildBoundaryTests(unittest.TestCase):
    def test_child_policy_changes_admitted_action_and_launch(self):
        action = {'argv': [sys.executable, '-c', 'pass'], 'cwd': str(Path.cwd()),
                  'scope': 'child-policy', 'identity': 'fixture', 'children': 'deny'}
        authority = Mock()
        with patch.object(client, 'run_managed', return_value=subprocess.CompletedProcess(action['argv'], 0)) as launch:
            self.assertEqual(client.run(action, authority), 0)
        self.assertEqual(authority.admit.call_args.args[0]['children'], 'deny')
        self.assertFalse(launch.call_args.kwargs['allow_children'])
        self.assertNotEqual(client.canonical(action), client.canonical(dict(action, children='inherit')))

    def test_generated_check_enforces_and_records_deny_policy(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder) / 'project'
            starter.init(root, 'Verify actual no-child acceptance execution')
            text = (root / 'project.grf').read_text()
            doc = json.loads(text[len(starter.HEADER):-5])
            doc['checks'][0]['children'] = 'deny'
            (root / 'project.grf').write_text(starter.HEADER + json.dumps(doc) + '\n```\n')
            starter.lifecycle(root, 'sign-in', task='Verify blocked nested subprocess launch')
            (root / 'checks/acceptance.py').write_text(
                'import subprocess,sys\nfrom pathlib import Path\nPath("root-proof").touch()\n'
                'subprocess.run([sys.executable,"-c","from pathlib import Path; Path(\'forbidden\').touch()"],check=True)\n')
            result = starter.run_checks(root)
            self.assertEqual(result['result'], 'FAIL')
            self.assertTrue((root / 'root-proof').exists(), 'Requested root really executed')
            self.assertFalse((root / 'forbidden').exists(), 'Descendant must not execute')
            receipt = json.loads((root / result['receipt']).read_text())
            self.assertEqual(receipt['checks'][0]['children'], 'deny')

    def test_invalid_policy_rejected_before_admission(self):
        authority = Mock()
        with self.assertRaises(ValueError):
            client.run({'argv': ['never-launch'], 'cwd': '.', 'children': 'sometimes'}, authority)
        authority.admit.assert_not_called()

    @unittest.skipUnless(sys.platform == 'linux', 'Linux session escape')
    def test_escaped_double_fork_cleanup_on_timeout_and_cancel(self):
        for outcome in ('timeout', 'cancel'):
            with self.subTest(outcome=outcome), tempfile.TemporaryDirectory() as folder:
                root = Path(folder)
                escaped = ('import os,time; from pathlib import Path; '
                           '\nif os.fork(): os._exit(0)\n'
                           'os.setsid(); Path("escaped.pid").write_text(str(os.getpid())); time.sleep(30)')
                code = ('import subprocess,sys,time; subprocess.Popen([sys.executable,"-c",sys.argv[1]],'
                        'start_new_session=True); time.sleep(30)')
                event = threading.Event()
                def stop():
                    deadline = time.monotonic() + 3
                    while not (root / 'escaped.pid').exists() and time.monotonic() < deadline:
                        time.sleep(.01)
                    event.set()
                watcher = threading.Thread(target=stop) if outcome == 'cancel' else None
                if watcher:
                    watcher.start()
                try:
                    expected = InterruptedError if outcome == 'cancel' else subprocess.TimeoutExpired
                    with self.assertRaises(expected):
                        managed.run_managed([sys.executable, '-c', code, escaped], cwd=root, timeout=1,
                                            capture_output=True, cancel=event)
                    pid = int((root / 'escaped.pid').read_text())
                    self.assertFalse(alive(pid), 'Escaped double-fork descendant survived')
                finally:
                    if watcher:
                        watcher.join(timeout=4)
                    path = root / 'escaped.pid'
                    if path.exists() and alive(int(path.read_text())):
                        os.kill(int(path.read_text()), signal.SIGKILL)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux controller-death supervision')
    def test_controller_death_cleans_escaped_child(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            escaped = 'import os,time; from pathlib import Path; Path("escaped.pid").write_text(str(os.getpid())); time.sleep(30)'
            root_code = 'import subprocess,sys,time; subprocess.Popen([sys.executable,"-c",sys.argv[1]],start_new_session=True); time.sleep(30)'
            controller = ('import sys; sys.path.insert(0,sys.argv[1]); import grf_process; '
                          'grf_process.run_managed([sys.executable,"-c",sys.argv[2],sys.argv[3]],cwd=".",timeout=25)')
            process = subprocess.Popen([sys.executable, '-c', controller, str(Path(managed.__file__).parent), root_code, escaped],
                                       cwd=root, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                deadline = time.monotonic() + 4
                while not (root / 'escaped.pid').exists() and time.monotonic() < deadline:
                    time.sleep(.01)
                pid = int((root / 'escaped.pid').read_text())
                self.assertTrue(alive(pid))
                process.kill()
                process.wait(timeout=3)
                deadline = time.monotonic() + 4
                while alive(pid) and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertFalse(alive(pid), 'Controller death left escaped descendant')
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                path = root / 'escaped.pid'
                if path.exists() and alive(int(path.read_text())):
                    os.kill(int(path.read_text()), signal.SIGKILL)

    def test_cleanup_preserves_unrelated_caller_child(self):
        sibling = subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(20)'])
        try:
            result = managed.run_managed([sys.executable, '-c', 'pass'], cwd='.', timeout=3)
            self.assertEqual(result.returncode, 0)
            self.assertIsNone(sibling.poll(), 'Cleanup touched an unrelated caller child')
        finally:
            sibling.kill()
            sibling.wait(timeout=3)

    @unittest.skipUnless(sys.platform == 'linux', 'POSIX signal status')
    def test_requested_signal_exit_is_preserved(self):
        result = managed.run_managed([sys.executable, '-c', 'import os,signal; os.kill(os.getpid(),signal.SIGTERM)'], cwd='.', timeout=3)
        self.assertEqual(result.returncode, -signal.SIGTERM)

    @unittest.skipUnless(sys.platform == 'linux', 'Linux session escape')
    def test_session_escaped_grandchild_is_cleaned_on_normal_exit(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            escaped = 'import os,time; from pathlib import Path; Path("escaped.pid").write_text(str(os.getpid())); time.sleep(30)'
            command = ('import subprocess,sys,time; from pathlib import Path; '
                       'subprocess.Popen([sys.executable,"-c",sys.argv[1]],start_new_session=True); '
                       '\nwhile not Path("escaped.pid").exists(): time.sleep(.01)')
            try:
                result = managed.run_managed([sys.executable, '-c', command, escaped], cwd=root, timeout=5)
                self.assertEqual(result.returncode, 0)
                pid = int((root / 'escaped.pid').read_text())
                deadline = time.monotonic() + 2
                while alive(pid) and time.monotonic() < deadline:
                    time.sleep(.02)
                self.assertFalse(alive(pid), 'setsid descendant survived successful return')
            finally:
                path = root / 'escaped.pid'
                if path.exists() and alive(int(path.read_text())):
                    os.kill(int(path.read_text()), signal.SIGKILL)

    def test_no_children_blocks_actual_subprocess_before_marker(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            code = 'import subprocess,sys; subprocess.run([sys.executable,"-c","from pathlib import Path; Path(\'forbidden\').touch()"],check=True)'
            result = managed.run_managed([sys.executable, '-c', code], cwd=root, timeout=5,
                                         capture_output=True, allow_children=False)
            self.assertNotEqual(result.returncode, 0)
            self.assertFalse((root / 'forbidden').exists())

    def test_no_children_still_allows_root_and_threads(self):
        with tempfile.TemporaryDirectory() as folder:
            result = managed.run_managed([sys.executable, '-c',
                'import threading; t=threading.Thread(target=lambda:None); t.start(); t.join(); print("root-ran")'],
                cwd=folder, timeout=5, capture_output=True, allow_children=False)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(result.stdout.strip(), b'root-ran')


if __name__ == '__main__':
    unittest.main()

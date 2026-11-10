"""Offline recipient tests. Run: python -m unittest test_client -v."""
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import Mock, patch

import grf_client as client


class ClientTests(unittest.TestCase):
    def setUp(self):
        self.action = {'argv': ['example', 'argument'], 'cwd': '/',
                       'scope': 'test', 'identity': 'test'}

    def test_denial_never_launches(self):
        authority = Mock()
        authority.admit.side_effect = client.Denied()
        with patch.object(client, 'run_managed') as launch:
            with self.assertRaises(client.Denied):
                client.run(self.action, authority)
            launch.assert_not_called()

    def test_allowed_exact_action_and_child_status(self):
        authority = Mock()
        with patch.object(client, 'run_managed', return_value=Mock(returncode=23)) as launch:
            self.assertEqual(client.run(self.action, authority), 23)
            authority.admit.assert_called_once_with(self.action)
            self.assertEqual(launch.call_args.args[0], self.action['argv'])
            self.assertEqual(launch.call_args.kwargs['cwd'], self.action['cwd'])
            self.assertNotIn('shell', launch.call_args.kwargs)

    def test_original_action_mutation_cannot_change_launch(self):
        authority = Mock()
        authority.admit.side_effect = lambda _: self.action['argv'].append('changed')
        with patch.object(client, 'run_managed', return_value=Mock(returncode=0)) as launch:
            client.run(self.action, authority)
            self.assertEqual(launch.call_args.args[0], ['example', 'argument'])

    def test_duplicate_and_nonfinite_json_rejected(self):
        for raw in ('{"a":1,"a":2}', '{"a":NaN}', '{"a":Infinity}'):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                client.strict_json(raw)

    def test_invalid_grants_never_consumed(self):
        for grant in ({'allowed': True, 'grant': 'short', 'ttl': 1},
                      {'allowed': True, 'grant': 'x'*32, 'ttl': True},
                      {'allowed': True, 'grant': 'x'*32, 'ttl': 0},
                      {'allowed': True, 'grant': 'x'*32, 'ttl': 61}):
            authority = object.__new__(client.Client)
            authority.config = {'project': 'test', 'policy': 'v1'}
            authority.request = Mock(return_value=grant)
            with self.subTest(grant=grant), self.assertRaises(client.Denied):
                authority.admit(self.action)
            self.assertEqual(authority.request.call_count, 1)

    def test_consumption_must_match_action(self):
        authority = object.__new__(client.Client)
        authority.config = {'project': 'test', 'policy': 'v1'}
        authority.request = Mock(side_effect=[
            {'allowed': True, 'grant': 'x'*32, 'ttl': 5},
            {'allowed': True, 'action': 'different', 'policy': 'v1'}])
        with self.assertRaises(client.Denied):
            authority.admit(self.action)

    def test_config_paths_are_relative_to_config(self):
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder)/'enrollment.json'
            path.write_text(json.dumps({'host': 'example.invalid', 'port': 443,
                'ca': 'ca.pem', 'cert': 'client.pem', 'key': 'client.key',
                'project': 'test', 'policy': 'v1'}))
            config = client.load_config(path)
            self.assertEqual(config['key'], str((Path(folder)/'client.key').resolve()))

    def test_relay_config_is_strict_and_credential_path_is_relative(self):
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder)/'enrollment.json'
            config={'host':'example.invalid','port':443,'ca':'ca.pem','cert':'client.pem','key':'client.key','project':'test','policy':'v1',
                    'relay':{'host':'grf-test.servicebus.windows.net','path':'test','key_name':'sender','key_file':'send.key'}}
            path.write_text(json.dumps(config))
            self.assertEqual(client.load_config(path)['relay']['key_file'],str((Path(folder)/'send.key').resolve()))
            for bad in ({'host':'https://example.com'}, {'key':'inline-secret'}, {'key_name':'bad/name'}, {'key_file':False}):
                altered=dict(config,relay=dict(config['relay'],**bad))
                path.write_text(json.dumps(altered))
                with self.subTest(bad=bad),self.assertRaises(ValueError):client.load_config(path)


if __name__ == '__main__':
    unittest.main()

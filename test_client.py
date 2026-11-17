"""Offline recipient tests. Run: python -m unittest test_client -v."""
import json
from pathlib import Path
import tempfile
import unittest
import time
from unittest.mock import Mock, patch

import grf_client as client


class ClientTests(unittest.TestCase):
    def test_open_signup_and_local_credential_protection(self):
        import grf_enroll
        import grf_starter
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder)/'project'
            grf_starter.init(root,'Test open enrollment')
            def response(host,path,value,account=None,secret=None):
                if path=='/v1/enroll':
                    self.assertEqual(set(value),{'account','credential_hash'})
                    self.assertEqual(len(value['credential_hash']),64)
                    account=value['account']
                return {'allowed':True,'account':account,'project':'public-'+account,'policy':'public-1','expires':int(time.time()+86400)}
            with patch.object(grf_enroll,'request',side_effect=response):
                self.assertTrue(grf_enroll.enroll(root,'example.invalid')['enrolled'])
                key=(root/'credentials/access.key').read_bytes()
                self.assertTrue(grf_enroll.enroll(root,'example.invalid')['enrolled'])
                self.assertEqual(key,(root/'credentials/access.key').read_bytes())
            config=client.load_config(root/'credentials/enrollment.json')
            self.assertEqual(config['transport'],'public-https')
            self.assertIn('/credentials/',(root/'.gitignore').read_text())
            self.assertEqual(grf_starter.project(root)['admission']['mode'],'remote')

    def test_public_client_registers_hash_before_requesting_grant(self):
        authority=object.__new__(client.Client)
        authority.config={'transport':'public-https','account':'a'*32,'project':'public-'+'a'*32,
                          'policy':'public-1','expires':time.time()+30*86400}
        binding={'action':__import__('hashlib').sha256(client.canonical(self.action)).hexdigest(),
                 'project':authority.config['project'],'policy':'public-1'}
        authority.request=Mock(side_effect=[{'allowed':True},{'allowed':True,'grant':'x'*32,'ttl':10},
                                          {'allowed':True,'action':binding['action'],'policy':'public-1'}])
        authority.admit(self.action)
        self.assertEqual(authority.request.call_args_list[0].args,(binding,'/v1/register'))
        self.assertNotIn('argv',str(authority.request.call_args_list))

    def test_public_registration_denial_never_issues_or_launches(self):
        authority=object.__new__(client.Client)
        authority.config={'transport':'public-https','project':'public-'+'a'*32,'policy':'public-1','expires':time.time()+30*86400}
        authority.request=Mock(side_effect=client.Denied())
        with patch.object(client,'run_managed') as launch,self.assertRaises(client.Denied):
            client.run(self.action,authority)
        launch.assert_not_called()
        self.assertEqual(authority.request.call_count,1)

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

"""MIT-licensed GRF admission client. No private evaluator or policy is included."""
import argparse
import hashlib
import http.client
import json
from pathlib import Path
import re
import ssl
import subprocess
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))
from grf_process import run_managed

VERSION = '0.4.0'


class Denied(Exception):
    """No authenticated, valid admission was obtained."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(',', ':'), ensure_ascii=True).encode()


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise ValueError('duplicate field')
            result[key] = value
        return result
    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(ValueError('constant')))
    except RecursionError:
        raise ValueError('invalid JSON') from None


def read_action(path):
    raw = Path(path).read_bytes()
    if len(raw) > 65536:
        raise ValueError('document too large')
    text = raw.decode('utf-8').replace('\r\n', '\n')
    start = '```grf:context id="downstream-example"\n'
    if not text.startswith(start) or not text.endswith('\n```\n'):
        raise ValueError('invalid document envelope')
    document = strict_json(text[len(start):-5])
    if not isinstance(document, dict) or document.get('format') != 'grf.downstream-preview/v1':
        raise ValueError('unsupported format')
    action = document.get('action')
    if not isinstance(action, dict) or set(action) != {'argv', 'cwd', 'scope', 'identity'}:
        raise ValueError('invalid action')
    if (not isinstance(action['argv'], list) or not action['argv']
            or len(action['argv']) > 128
            or any(type(v) is not str or '\0' in v or len(v) > 4096 for v in action['argv'])
            or not action['argv'][0]
            or any(type(action[k]) is not str or not action[k] or '\0' in action[k]
                   for k in ('cwd', 'scope', 'identity'))):
        raise ValueError('invalid action fields')
    return action


def load_config(path):
    path = Path(path).resolve()
    if path.stat().st_size > 16384:
        raise ValueError('configuration too large')
    config = strict_json(path.read_bytes())
    required = {'host', 'port', 'ca', 'cert', 'key', 'project', 'policy'}
    if not isinstance(config, dict) or set(config) not in (required, required | {'relay'}):
        raise ValueError('invalid enrollment fields')
    if type(config['port']) is not int or not 1 <= config['port'] <= 65535:
        raise ValueError('invalid port')
    if any(type(config[k]) is not str or not config[k] or len(config[k]) > 1024
           or '\0' in config[k] for k in required - {'port'}):
        raise ValueError('invalid enrollment value')
    if any(c in config['host'] for c in '/@?#') or any(c.isspace() for c in config['host']):
        raise ValueError('host must be a hostname or IP, not a URL')
    for k in ('ca', 'cert', 'key'):
        config[k] = str((path.parent / config[k]).resolve())
    if 'relay' in config:
        relay=config['relay']
        if not isinstance(relay,dict) or set(relay)!={'host','path','key_name','key_file'}:
            raise ValueError('Invalid relay configuration')
        if any(type(v) is not str or not v or '\0' in v or len(v)>1024 for v in relay.values()):
            raise ValueError('Invalid relay configuration')
        if (not re.fullmatch(r'[a-z0-9][a-z0-9-]{4,48}\.servicebus\.windows\.net',relay['host'])
                or any(not re.fullmatch(r'[a-zA-Z0-9_-]{1,80}',relay[k]) for k in ('path','key_name'))):
            raise ValueError('Invalid relay endpoint')
        relay['key_file']=str((path.parent/relay['key_file']).resolve())
    return config


class Client:
    def __init__(self, config):
        self.config = dict(config)
        self.context = ssl.create_default_context(cafile=config['ca'])
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self.context.load_cert_chain(config['cert'], config['key'])

    def request(self, value):
        if 'relay' in self.config:
            from grf_relay import RelayHTTPSConnection
            c = RelayHTTPSConnection(self.config,self.context)
        else:
            c = http.client.HTTPSConnection(self.config['host'], self.config['port'],
                                            context=self.context, timeout=4)
        try:
            c.request('POST', '/v1/admission', canonical(value), {'Content-Type': 'application/json'})
            r = c.getresponse()
            raw = r.read(4097)
            if r.status != 200 or len(raw) > 4096 or r.getheader('Content-Type') != 'application/json':
                raise Denied()
            result = strict_json(raw)
            if not isinstance(result, dict) or result.get('allowed') is not True:
                raise Denied()
            return result
        except (OSError, ValueError, http.client.HTTPException):
            raise Denied() from None
        finally:
            c.close()

    def admit(self, action):
        binding = {'action': hashlib.sha256(canonical(action)).hexdigest(),
                   'project': self.config['project'], 'policy': self.config['policy']}
        issued = self.request(dict(binding, phase='issue'))
        if (set(issued) != {'allowed', 'grant', 'ttl'}
                or type(issued['grant']) is not str or not 16 <= len(issued['grant']) <= 256
                or type(issued['ttl']) not in (int, float) or not 0 < issued['ttl'] <= 60):
            raise Denied()
        consumed = self.request(dict(binding, phase='consume', grant=issued['grant']))
        if consumed != {'allowed': True, 'action': binding['action'], 'policy': binding['policy']}:
            raise Denied()


def run(action, client):
    # Freeze the caller's data before hashing and launching; no shell interpolation.
    action = strict_json(canonical(action))
    client.admit(action)
    return run_managed(action['argv'], cwd=action['cwd'], timeout=30).returncode


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version', version=VERSION)
    parser.add_argument('document')
    parser.add_argument('--config', required=True, help='Separately provisioned enrollment JSON')
    parser.add_argument('--check', action='store_true', help='Validate local document/config only; no API call or launch')
    args = parser.parse_args()
    try:
        action, config = read_action(args.document), load_config(args.config)
        if args.check:
            print('Local syntax valid. No server admission or credential validation performed.')
            return 0
        return run(action, Client(config))
    except (Denied, OSError, ValueError, subprocess.SubprocessError):
        print('GRF could not complete the request. No private server details are returned.', file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

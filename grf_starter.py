"""Portable, MIT-licensed downstream starter. Local evidence is not a security boundary."""
import argparse
import ast
from contextlib import contextmanager
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import uuid

from grf_client import Client, Denied, canonical, load_config, strict_json

VERSION = '0.3.0-rc1'
HEADER = '```grf:context id="downstream-project"\n'
REQUIRED = 'REG-PROJECT-ACCEPTANCE'


def now():
    return datetime.now(timezone.utc).isoformat()


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def write_json(path, value):
    path = Path(path)
    temp = path.with_name(path.name + '.' + uuid.uuid4().hex + '.tmp')
    temp.write_text(json.dumps(value, indent=2) + '\n', encoding='utf-8')
    os.replace(temp, path)


def inside(root, name):
    path = (root / name).resolve()
    if path == root or root not in path.parents:
        raise ValueError('Path must stay inside the project: ' + str(name))
    return path


def init(target, intent):
    target = Path(target).resolve()
    if not intent.strip():
        raise ValueError('A concrete project intent is required')
    # mkdir is exclusive; never adopt or overwrite an existing directory.
    target.mkdir(parents=False, exist_ok=False)
    runtime = target / '.grf-runtime'
    runtime.mkdir()
    source = Path(__file__).resolve().parent
    for name in ('grf_starter.py', 'grf_client.py'):
        shutil.copyfile(source / name, runtime / name)
    pins = {name: sha(runtime / name) for name in ('grf_starter.py', 'grf_client.py')}
    launcher = '''"""Project-local pinned entry point. No installed-runtime fallback."""
import hashlib, json, pathlib, runpy, sys
root = pathlib.Path(__file__).resolve().parent
runtime = root / '.grf-runtime'
pins = json.loads((runtime / 'pins.json').read_text(encoding='utf-8'))
if set(pins) != {'grf_starter.py', 'grf_client.py'}:
    raise SystemExit('Invalid runtime pins; restore the verified release')
for name, expected in pins.items():
    if hashlib.sha256((runtime / name).read_bytes()).hexdigest() != expected:
        raise SystemExit('Runtime changed; restore the verified release: ' + name)
sys.path.insert(0, str(runtime))
runpy.run_path(str(runtime / 'grf_starter.py'), run_name='__main__')
'''
    (target / 'grf.py').write_text(launcher, encoding='utf-8')
    write_json(runtime / 'pins.json', pins)
    (target / 'checks').mkdir()
    (target / 'checks' / 'acceptance.py').write_text(
        '"""Replace this with assertions against your actual project behavior."""\n'
        'raise SystemExit("FAIL: project acceptance has not been implemented")\n', encoding='utf-8')
    (target / '.grf').mkdir()
    (target / '.grf' / 'receipts').mkdir()
    doc = {'format': 'grf.downstream-project/v1', 'name': target.name, 'intent': intent,
           'scope': {'allowed': ['Implement and verify the stated project intent'],
                     'excluded': ['Unrequested publication, spending, and credential disclosure']},
           'checks': [{'id': REQUIRED, 'argv': ['{python}', 'checks/acceptance.py'],
                       'timeout_seconds': 60}],
           'admission': {'mode': 'local', 'enrollment': 'credentials/enrollment.json'}}
    (target / 'project.grf').write_text(HEADER + json.dumps(doc, indent=2) + '\n```\n', encoding='utf-8')
    entry = {'authority': 'project.grf', 'runner': 'python grf.py',
             'workflow': ['Read project.grf and inspect session status.',
                          'Resume the active session; never replace unfinished work.',
                          'Otherwise sign in with a concrete task.',
                          'Run check. Initial acceptance fails intentionally; implement real assertions.',
                          'Complete with nonempty evidence; sign out only after fresh checks pass.'],
             'limits': 'Local runner and hashes do not prevent owner modification or prove test quality.'}
    (target / 'AGENTS.grf').write_text('```grf:context id="agent-entry"\n' +
                                     json.dumps(entry, indent=2) + '\n```\n', encoding='utf-8')
    (target / '.gitignore').write_text('.grf/\ncredentials/\n__pycache__/\n*.pyc\n', encoding='utf-8')
    return {'project': str(target), 'version': VERSION, 'acceptance': 'NOT IMPLEMENTED',
            'next': 'Read AGENTS.grf, then python grf.py session sign-in --task "your concrete task"'}


def project(root):
    path = root / 'project.grf'
    text = path.read_text(encoding='utf-8').replace('\r\n', '\n')
    if len(text) > 131072 or not text.startswith(HEADER) or not text.endswith('\n```\n'):
        raise ValueError('Invalid project GRF envelope')
    doc = strict_json(text[len(HEADER):-5])
    if not isinstance(doc, dict) or doc.get('format') != 'grf.downstream-project/v1':
        raise ValueError('Unsupported project format')
    checks = doc.get('checks')
    if not isinstance(checks, list) or not checks:
        raise ValueError('Empty check suite is not validation')
    ids = []
    for check in checks:
        if not isinstance(check, dict) or set(check) != {'id', 'argv', 'timeout_seconds'}:
            raise ValueError('Invalid check fields')
        ident, argv, timeout = check['id'], check['argv'], check['timeout_seconds']
        if not isinstance(ident, str) or not re.fullmatch(r'REG-[A-Z0-9-]+', ident) or ident in ids:
            raise ValueError('Invalid or duplicate check ID')
        ids.append(ident)
        if not isinstance(argv, list) or not argv or any(type(a) is not str or not a or '\0' in a for a in argv):
            raise ValueError('Check argv must be a nonempty list of strings')
        if type(timeout) is not int or not 1 <= timeout <= 3600:
            raise ValueError('Check timeout must be 1..3600 seconds')
    if REQUIRED not in ids:
        raise ValueError('Required project acceptance check was removed')
    admission = doc.get('admission')
    if not isinstance(admission, dict) or admission.get('mode') not in ('local', 'remote'):
        raise ValueError('Select explicit local or remote admission')
    return doc


@contextmanager
def locked(root):
    state_dir = root / '.grf'
    if not state_dir.is_dir():
        raise ValueError('Not an initialized project')
    lock = state_dir / 'writer.lock'
    fd = os.open(str(lock), os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        os.write(fd, canonical({'pid': os.getpid(), 'at': now()}))
        os.close(fd)
        yield
    finally:
        lock.unlink()


def state(root):
    path = root / '.grf' / 'session.json'
    return strict_json(path.read_bytes()) if path.exists() else None


def save(root, value, event):
    write_json(root / '.grf' / 'session.json', value)
    with (root / '.grf' / 'events.jsonl').open('a', encoding='utf-8') as stream:
        stream.write(json.dumps({'at': now(), 'event': event, 'session': value}) + '\n')


def require_active(root):
    value = state(root)
    if not value or value.get('status') == 'signed-out':
        raise ValueError('Sign in with a concrete task first')
    return value


def run_checks(root):
    doc = project(root)
    active = require_active(root)
    ids = [c['id'] for c in doc['checks']]
    if not set(active['acceptance_ids']).issubset(ids):
        raise ValueError('A check bound at sign-in was removed')
    report = {'started_at': now(), 'session_id': active['id'],
              'project_sha256': sha(root / 'project.grf'), 'checks': []}
    for check in doc['checks']:
        argv = [sys.executable if a == '{python}' else a for a in check['argv']]
        item = {'id': check['id'], 'argv': argv, 'started_at': now()}
        try:
            if len(argv) > 1 and argv[0] == sys.executable and argv[1].endswith('.py'):
                script = inside(root, argv[1])
                tree = ast.parse(script.read_text(encoding='utf-8'))
                statements = [node for node in tree.body if not isinstance(node, ast.Pass) and not
                              (isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant))]
                if not statements:
                    raise ValueError('Empty/comment/docstring-only check is not validation')
                item['script_sha256'] = sha(script)
            # Logs stay local. Remote admission sends the exact-action digest only.
            if doc['admission']['mode'] == 'remote':
                config = load_config(inside(root, doc['admission']['enrollment']))
                Client(config).admit({'argv': argv, 'cwd': str(root),
                                      'scope': check['id'], 'identity': active['id']})
            result = subprocess.run(argv, cwd=root, stdin=subprocess.DEVNULL,
                                    capture_output=True, timeout=check['timeout_seconds'])
            item.update(exit_code=result.returncode,
                        stdout=result.stdout.decode('utf-8', errors='replace')[-16000:],
                        stderr=result.stderr.decode('utf-8', errors='replace')[-16000:],
                        result='PASS' if result.returncode == 0 else 'FAIL')
        except (OSError, subprocess.SubprocessError, ValueError, SyntaxError, Denied) as error:
            item.update(exit_code=None, result='FAIL', error=type(error).__name__)
        item['finished_at'] = now()
        report['checks'].append(item)
    report.update(finished_at=now(), discovered=len(doc['checks']), executed=len(report['checks']),
                  passed=sum(c['result'] == 'PASS' for c in report['checks']))
    report['result'] = 'PASS' if report['passed'] == report['executed'] else 'FAIL'
    if sha(root / 'project.grf') != report['project_sha256']:
        report.update(result='FAIL', error='Project contract changed during checks')
    receipt = root / '.grf' / 'receipts' / (uuid.uuid4().hex + '.json')
    write_json(receipt, report)
    return {'result': report['result'], 'executed': report['executed'], 'passed': report['passed'],
            'receipt': str(receipt.relative_to(root)), 'sha256': sha(receipt)}


def lifecycle(root, action, task=None, evidence=None, summary=None):
    if action == 'status':
        return state(root) or {'status': 'no session'}
    if action == 'sign-in':
        current = state(root)
        if current and current.get('status') != 'signed-out':
            raise ValueError('Unfinished session exists; resume it')
        if not task or len(task.strip()) < 10:
            raise ValueError('Supply a concrete task of at least ten characters')
        doc = project(root)
        value = {'id': uuid.uuid4().hex, 'task': task.strip(), 'status': 'active', 'started_at': now(),
                 'acceptance_ids': [c['id'] for c in doc['checks']], 'completion': None}
    else:
        value = require_active(root)
        if action == 'resume':
            value['resumed_at'] = now()
        elif action == 'complete':
            if not summary or len(summary.strip()) < 10 or not evidence:
                raise ValueError('Provide a meaningful summary and at least one evidence file')
            files = {}
            for name in evidence:
                path = inside(root, name)
                if not path.is_file() or not path.stat().st_size:
                    raise ValueError('Evidence must be a nonempty project file')
                files[str(path.relative_to(root))] = sha(path)
            receipt = run_checks(root)
            if receipt['result'] != 'PASS':
                raise ValueError('Acceptance failed; receipt: ' + receipt['receipt'])
            if any(sha(inside(root, name)) != digest for name, digest in files.items()):
                raise ValueError('Evidence changed during validation')
            value['completion'] = {'summary': summary, 'evidence': files, 'receipt': receipt,
                                   'project_sha256': sha(root / 'project.grf'), 'at': now()}
        elif action == 'sign-out':
            complete = value.get('completion')
            if not complete:
                raise ValueError('Complete the task with passing checks and evidence first')
            if sha(root / 'project.grf') != complete['project_sha256']:
                raise ValueError('Project contract changed after completion')
            files = complete['evidence']
            if any(sha(inside(root, name)) != digest for name, digest in files.items()):
                raise ValueError('Completion evidence changed')
            old = complete['receipt']
            if sha(inside(root, old['receipt'])) != old['sha256']:
                raise ValueError('Completion receipt changed')
            receipt = run_checks(root)
            if receipt['result'] != 'PASS':
                raise ValueError('Fresh acceptance failed; receipt: ' + receipt['receipt'])
            if (sha(root / 'project.grf') != complete['project_sha256'] or
                    any(sha(inside(root, name)) != digest for name, digest in files.items())):
                raise ValueError('Evidence or contract changed during sign-out checks')
            value.update(status='signed-out', signed_out_at=now(), final_receipt=receipt)
        else:
            raise ValueError('Unknown session action')
    save(root, value, action)
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', action='version', version=VERSION)
    parser.add_argument('--project', default='.', help='Initialized project directory')
    sub = parser.add_subparsers(dest='command', required=True)
    create = sub.add_parser('init')
    create.add_argument('target')
    create.add_argument('--intent', required=True)
    sub.add_parser('check')
    session = sub.add_parser('session')
    session.add_argument('action', choices=['status', 'sign-in', 'resume', 'complete', 'sign-out'])
    session.add_argument('--task')
    session.add_argument('--evidence', action='append')
    session.add_argument('--summary')
    args = parser.parse_args()
    try:
        if args.command == 'init':
            result = init(args.target, args.intent)
        else:
            root = Path(args.project).resolve()
            with locked(root):
                result = run_checks(root) if args.command == 'check' else lifecycle(
                    root, args.action, args.task, args.evidence, args.summary)
        print(json.dumps(result, indent=2))
        return 1 if result.get('result') == 'FAIL' else 0
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('GRF: ' + str(error), file=sys.stderr)
        return 1


if __name__ == '__main__':
    raise SystemExit(main())

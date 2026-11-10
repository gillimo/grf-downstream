"""Verify extracted release integrity, not publisher identity. Standard library only."""
import hashlib
import json
from pathlib import Path
import sys


def verify(root):
    root = Path(root)
    manifest = json.loads((root/'MANIFEST.json').read_text(encoding='utf-8'))
    files = manifest['files']
    if not isinstance(files, dict) or not files:
        raise ValueError('Empty manifest')
    for name, expected in files.items():
        if not isinstance(name, str) or Path(name).name != name or '/' in name or '\\' in name:
            raise ValueError('Invalid manifest path')
        path = root/name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Missing or unsafe file: '+name)
        if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
            raise ValueError('Checksum mismatch: '+name)
    return len(files)


if __name__ == '__main__':
    try:
        count = verify(Path(__file__).resolve().parent)
    except (OSError, ValueError, KeyError, TypeError) as error:
        print('FAIL: '+str(error), file=sys.stderr)
        raise SystemExit(1)
    print('PASS: %d files match manifest. Verify publisher/checksum separately.' % count)

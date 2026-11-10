"""Real nested child lifecycle checks; fixtures leave no processes behind."""
import ctypes
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

import grf_process as managed


def alive(pid):
    if os.name == 'nt':
        api = ctypes.WinDLL('kernel32', use_last_error=True)
        api.OpenProcess.argtypes = [ctypes.c_ulong, ctypes.c_int, ctypes.c_ulong]
        api.OpenProcess.restype = ctypes.c_void_p
        api.WaitForSingleObject.argtypes = [ctypes.c_void_p, ctypes.c_ulong]
        api.CloseHandle.argtypes = [ctypes.c_void_p]
        handle = api.OpenProcess(0x100000, False, pid)
        if not handle:
            return False
        try:
            return api.WaitForSingleObject(handle, 0) == 258
        finally:
            api.CloseHandle(handle)
    status = Path('/proc') / str(pid) / 'stat'
    if status.exists() and status.read_text().split(') ', 1)[1].startswith('Z'):
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False


class ProcessTests(unittest.TestCase):
    def test_exact_argv_status_and_bounded_output(self):
        with tempfile.TemporaryDirectory() as folder:
            result = managed.run_managed([sys.executable, '-c',
                'import sys; assert sys.argv[1] == "argument with spaces"; '
                'sys.stdout.write("a"*200000+"END"); sys.stderr.write("b"*200000+"ERR"); sys.exit(23)',
                'argument with spaces'], cwd=folder, timeout=10, capture_output=True)
            self.assertEqual(result.returncode, 23)
            self.assertEqual(result.stdout, b'a' * (managed.OUTPUT_LIMIT - 3) + b'END')
            self.assertEqual(result.stderr, b'b' * (managed.OUTPUT_LIMIT - 3) + b'ERR')

    def tree(self, outcome):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            fixture = root / 'tree.py'
            fixture.write_text('''import os, subprocess, sys, time
from pathlib import Path
depth = int(sys.argv[1])
Path(str(depth)+'.pid').write_text(str(os.getpid()))
if depth:
    subprocess.Popen([sys.executable, __file__, str(depth-1)])
    while not Path('0.pid').exists(): time.sleep(.01)
if depth == 2 and sys.argv[-1] == 'exit': sys.exit(0)
time.sleep(30)
''')
            cancel = threading.Event()
            watcher = None
            if outcome == 'cancel':
                def stop():
                    until = time.monotonic() + 8
                    while not (root / '0.pid').exists() and time.monotonic() < until:
                        time.sleep(.01)
                    cancel.set()
                watcher = threading.Thread(target=stop)
                watcher.start()
            try:
                command = [sys.executable, str(fixture), '2', outcome]
                if outcome == 'exit':
                    self.assertEqual(managed.run_managed(command, cwd=root, timeout=10,
                                     capture_output=True).returncode, 0)
                else:
                    error = InterruptedError if outcome == 'cancel' else subprocess.TimeoutExpired
                    with self.assertRaises(error):
                        managed.run_managed(command, cwd=root, timeout=2, capture_output=True, cancel=cancel)
                self.assertEqual(len(list(root.glob('*.pid'))), 3, 'Nested processes actually started')
                for path in root.glob('*.pid'):
                    pid = int(path.read_text())
                    until = time.monotonic() + 3
                    while alive(pid) and time.monotonic() < until:
                        time.sleep(.02)
                    self.assertFalse(alive(pid), 'Surviving descendant: ' + path.name)
            finally:
                if watcher:
                    watcher.join(timeout=10)
                for path in root.glob('*.pid'):
                    pid = int(path.read_text())
                    if alive(pid):
                        os.kill(pid, signal.SIGTERM)

    def test_timeout_cleans_children_and_grandchildren(self):
        self.tree('timeout')

    def test_normal_exit_cleans_background_descendants(self):
        self.tree('exit')

    def test_cancellation_cleans_children_and_grandchildren(self):
        self.tree('cancel')

    def test_pre_cancel_never_launches(self):
        event = threading.Event()
        event.set()
        with patch.object(managed.subprocess, 'Popen') as launch:
            with self.assertRaises(InterruptedError):
                managed.run_managed(['must-not-run'], cwd='.', timeout=1, cancel=event)
            launch.assert_not_called()

    def test_platform_lifetime_boundary(self):
        if os.name != 'nt':
            result = managed.run_managed([sys.executable, '-c',
                'import os; assert os.getpid() == os.getpgrp() == os.getsid(0)'],
                cwd='.', timeout=3, capture_output=True)
            self.assertEqual(result.returncode, 0)
            return
        with tempfile.TemporaryDirectory() as folder:
            marker = Path(folder) / 'should-not-exist'
            with patch.object(managed.WindowsJob, 'assign', side_effect=OSError('Synthetic assignment failure')):
                with self.assertRaises(OSError):
                    managed.run_managed([sys.executable, '-c', 'from pathlib import Path; Path("should-not-exist").touch()'],
                                        cwd=folder, timeout=3)
            self.assertFalse(marker.exists())


if __name__ == '__main__':
    unittest.main()

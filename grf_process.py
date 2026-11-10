"""Cooperative command lifetime control. Not a hostile-code security sandbox.

Windows owns a job before releasing the launch broker; POSIX owns a process group.
Explicit POSIX session escapes and external service launches are outside this model.
"""
import ctypes
from ctypes import wintypes
import json
import os
import signal
import subprocess
import sys
import threading

OUTPUT_LIMIT = 16000


class WindowsJob:
    def __init__(self):
        self.handle = None
        self.api = ctypes.WinDLL('kernel32', use_last_error=True)

        class Basic(ctypes.Structure):
            _fields_ = [('process_time', ctypes.c_int64), ('job_time', ctypes.c_int64),
                        ('flags', wintypes.DWORD), ('minimum_working', ctypes.c_size_t),
                        ('maximum_working', ctypes.c_size_t), ('active_processes', wintypes.DWORD),
                        ('affinity', ctypes.c_size_t), ('priority', wintypes.DWORD),
                        ('scheduling', wintypes.DWORD)]

        class Io(ctypes.Structure):
            _fields_ = [(name, ctypes.c_uint64) for name in
                        ('read_count', 'write_count', 'other_count', 'read_bytes', 'write_bytes', 'other_bytes')]

        class Extended(ctypes.Structure):
            _fields_ = [('basic', Basic), ('io', Io), ('process_memory', ctypes.c_size_t),
                        ('job_memory', ctypes.c_size_t), ('peak_process_memory', ctypes.c_size_t),
                        ('peak_job_memory', ctypes.c_size_t)]

        self.api.CreateJobObjectW.argtypes = [ctypes.c_void_p, wintypes.LPCWSTR]
        self.api.CreateJobObjectW.restype = wintypes.HANDLE
        self.api.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
        self.api.SetInformationJobObject.restype = wintypes.BOOL
        self.api.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
        self.api.AssignProcessToJobObject.restype = wintypes.BOOL
        self.api.CloseHandle.argtypes = [wintypes.HANDLE]
        self.api.CloseHandle.restype = wintypes.BOOL
        self.handle = self.api.CreateJobObjectW(None, None)
        if not self.handle:
            raise OSError('Cannot create process job')
        info = Extended()
        info.basic.flags = 0x2000  # KILL_ON_JOB_CLOSE; no breakaway permission.
        if not self.api.SetInformationJobObject(self.handle, 9, ctypes.byref(info), ctypes.sizeof(info)):
            self.close()
            raise OSError('Cannot configure process job')

    def assign(self, process):
        if not self.api.AssignProcessToJobObject(self.handle, int(process._handle)):
            raise OSError('Cannot assign process job')

    def close(self):
        if self.handle:
            if not self.api.CloseHandle(self.handle):
                raise OSError('Cannot close process job')
            self.handle = None


def run_managed(argv, *, cwd, timeout, capture_output=False, cancel=None):
    """Run exact argv; always clean up the job/group, including on normal exit.

    cancel is an optional threading.Event. Captured streams retain only their last
    OUTPUT_LIMIT bytes. A cancelled call raises InterruptedError after cleanup.
    """
    argv = list(argv)
    if cancel is not None and cancel.is_set():
        raise InterruptedError('Command cancelled')
    job = WindowsJob() if os.name == 'nt' else None
    process = None
    readers = []
    tails = [bytearray(), bytearray()]

    def drain(stream, tail):
        try:
            while True:
                chunk = stream.read(8192)
                if not chunk:
                    break
                tail.extend(chunk)
                del tail[:-OUTPUT_LIMIT]
        finally:
            stream.close()

    try:
        command = argv
        if job:
            # No requested command executes until the broker belongs to the job.
            broker = ('import json,subprocess,sys; a=json.loads(sys.stdin.buffer.readline()); '
                      'r=subprocess.run(a,stdin=subprocess.DEVNULL,shell=False); sys.exit(r.returncode)')
            command = [sys.executable, '-I', '-c', broker]
        process = subprocess.Popen(command, cwd=cwd, shell=False,
                                   stdin=subprocess.PIPE if job else subprocess.DEVNULL,
                                   stdout=subprocess.PIPE if capture_output else None,
                                   stderr=subprocess.PIPE if capture_output else None,
                                   start_new_session=os.name != 'nt')
        if capture_output:
            for stream, tail in zip((process.stdout, process.stderr), tails):
                thread = threading.Thread(target=drain, args=(stream, tail), daemon=True)
                readers.append(thread)
                thread.start()
        if job:
            job.assign(process)
            process.stdin.write(json.dumps(argv).encode() + b'\n')
            process.stdin.close()
        import time
        deadline = time.monotonic() + timeout
        while True:
            if cancel is not None and cancel.is_set():
                raise InterruptedError('Command cancelled')
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise subprocess.TimeoutExpired(argv, timeout)
            try:
                code = process.wait(timeout=min(remaining, 0.1))
                break
            except subprocess.TimeoutExpired:
                continue
    finally:
        try:
            if job:
                job.close()
            elif process:
                try:
                    os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
        finally:
            if process:
                if process.poll() is None:
                    process.kill()
                process.wait()
                if process.stdin and not process.stdin.closed:
                    process.stdin.close()
            for thread in readers:
                thread.join(timeout=3)
            if any(thread.is_alive() for thread in readers):
                raise OSError('Output stream remained open outside the managed process group')
    return subprocess.CompletedProcess(argv, code,
        bytes(tails[0]) if capture_output else None, bytes(tails[1]) if capture_output else None)

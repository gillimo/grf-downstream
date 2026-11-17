"""Cooperative command lifetime control. Not a hostile-code security sandbox.

Windows owns a job before releasing the launch broker. Linux uses a dedicated
subreaper to collect session-escaped descendants. Other POSIX hosts use a process
group. External service launches remain outside this model. Optional no-child
mode blocks process creation on supported Windows/Linux hosts, not in-process
actions, exec replacement, or requests to existing external services.
"""
import ctypes
from ctypes import wintypes
import json
import os
import signal
import subprocess
import sys
import threading
import time
from pathlib import Path

OUTPUT_LIMIT = 16000


class WindowsJob:
    def __init__(self, *, allow_children=True):
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
        if not allow_children:
            # The trusted broker and requested root occupy the two allowed slots.
            info.basic.flags |= 0x8  # JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            info.basic.active_processes = 2
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


def run_managed(argv, *, cwd, timeout, capture_output=False, cancel=None, allow_children=True):
    """Run exact argv; always clean up the job/group, including on normal exit.

    cancel is an optional threading.Event. Captured streams retain only their last
    OUTPUT_LIMIT bytes. A cancelled call raises InterruptedError after cleanup.
    """
    argv = list(argv)
    if type(allow_children) is not bool:
        raise ValueError('allow_children must be a boolean')
    if cancel is not None and cancel.is_set():
        raise InterruptedError('Command cancelled')
    if sys.platform == 'linux':
        return _run_linux(argv, cwd=cwd, timeout=timeout, capture_output=capture_output,
                          cancel=cancel, allow_children=allow_children)
    if not allow_children and os.name != 'nt':
        raise OSError('No-child enforcement is unsupported on this platform')
    job = WindowsJob(allow_children=allow_children) if os.name == 'nt' else None
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


def _linux_no_children():
    """Deny process creation in the requested process; permit normal threads.

    This is a narrow process-creation restriction, not a syscall sandbox. Existing
    external services, in-process actions and exec replacement remain possible.
    """
    import platform
    machine = platform.machine()
    if machine == 'x86_64':
        arch, clone, forks = 0xc000003e, 56, (57, 58)
    elif machine in ('aarch64', 'arm64'):
        arch, clone, forks = 0xc00000b7, 220, ()
    else:
        raise OSError('No-child filter unsupported on this Linux architecture')

    class Filter(ctypes.Structure):
        _fields_ = [('code', ctypes.c_ushort), ('jt', ctypes.c_ubyte),
                    ('jf', ctypes.c_ubyte), ('k', ctypes.c_uint32)]

    class Program(ctypes.Structure):
        _fields_ = [('length', ctypes.c_ushort), ('filter', ctypes.POINTER(Filter))]

    deny = 0x00050001  # SECCOMP_RET_ERRNO | EPERM
    instructions = [(0x20, 0, 0, 4), (0x15, 1, 0, arch), (0x06, 0, 0, 0x80000000),
                    (0x20, 0, 0, 0)]
    if machine == 'x86_64':
        instructions += [(0x35, 0, 1, 0x40000000), (0x06, 0, 0, deny)]
    for number in forks:
        instructions += [(0x15, 0, 1, number), (0x06, 0, 0, deny)]
    # clone3's pointed-to flags cannot be inspected by classic seccomp. ENOSYS
    # lets libc fall back to inspectable clone for threads, while forks fail.
    instructions += [(0x15, 0, 1, 435), (0x06, 0, 0, 0x00050026),
                     (0x15, 0, 3, clone), (0x20, 0, 0, 16),
                     (0x45, 1, 0, 0x10000), (0x06, 0, 0, deny),
                     (0x06, 0, 0, 0x7fff0000)]
    filters = (Filter * len(instructions))(*(Filter(*i) for i in instructions))
    program = Program(len(instructions), filters)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.argtypes = [ctypes.c_int] + [ctypes.c_ulong] * 4
    if libc.prctl(38, 1, 0, 0, 0) != 0:  # PR_SET_NO_NEW_PRIVS
        raise OSError(ctypes.get_errno(), 'Cannot set no-new-privileges')
    address = ctypes.cast(ctypes.byref(program), ctypes.c_void_p).value
    if libc.prctl(22, 2, address, 0, 0) != 0:  # PR_SET_SECCOMP, FILTER
        raise OSError(ctypes.get_errno(), 'Cannot install no-child filter')


def _linux_supervise(result_fd):
    """Dedicated single-threaded subreaper; never adopts other caller children."""
    spec = json.loads(sys.stdin.buffer.readline())
    stopped = [False]
    for sig in (signal.SIGTERM, signal.SIGINT):
        signal.signal(sig, lambda *_: stopped.__setitem__(0, True))
    libc = ctypes.CDLL(None, use_errno=True)
    result = {'cleanup_complete': False}
    root = None
    try:
        if libc.prctl(36, 1, 0, 0, 0) != 0:  # PR_SET_CHILD_SUBREAPER
            raise OSError('Cannot become descendant subreaper')
        if libc.prctl(1, signal.SIGTERM, 0, 0, 0) != 0:  # PR_SET_PDEATHSIG
            raise OSError('Cannot monitor controller lifetime')
        if os.getppid() != spec['controller_pid']:
            raise InterruptedError('Controller exited before launch')
        root = subprocess.Popen(spec['argv'], cwd=spec['cwd'], stdin=subprocess.DEVNULL,
                                start_new_session=True,
                                preexec_fn=None if spec['allow_children'] else _linux_no_children)
        deadline = time.monotonic() + spec['timeout']
        while root.poll() is None:
            if stopped[0]:
                raise InterruptedError('Command cancelled')
            if time.monotonic() >= deadline:
                raise subprocess.TimeoutExpired(spec['argv'], spec['timeout'])
            time.sleep(.02)
        result['returncode'] = root.returncode
    except subprocess.TimeoutExpired:
        result['error'] = 'timeout'
    except InterruptedError:
        result['error'] = 'cancelled'
    except Exception as error:
        result['error'] = type(error).__name__
    finally:
        try:
            if root:
                try:
                    os.killpg(root.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            deadline = time.monotonic() + 5
            while True:
                # A killed ancestor's setsid/double-fork descendants are adopted
                # by this subreaper. Kill and reap until the kernel reports ECHILD.
                children = Path('/proc/self/task') / str(os.getpid()) / 'children'
                for value in children.read_text().split():
                    try:
                        os.kill(int(value), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                try:
                    while os.waitpid(-1, os.WNOHANG)[0]:
                        pass
                except ChildProcessError:
                    result['cleanup_complete'] = True
                    break
                if time.monotonic() >= deadline:
                    raise OSError('Descendants did not terminate within cleanup deadline')
                time.sleep(.01)
        except Exception:
            result['error'] = 'cleanup-failed'
        try:
            os.write(result_fd, json.dumps(result).encode())
        except BrokenPipeError:
            pass  # Controller died; cleanup still ran before this report.
        os.close(result_fd)


def _run_linux(argv, *, cwd, timeout, capture_output, cancel, allow_children):
    read_fd, write_fd = os.pipe()
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
        process = subprocess.Popen([sys.executable, '-I', str(Path(__file__).resolve()),
                                    '--linux-supervisor', str(write_fd)], cwd=cwd,
                                   stdin=subprocess.PIPE, pass_fds=(write_fd,), start_new_session=True,
                                   stdout=subprocess.PIPE if capture_output else None,
                                   stderr=subprocess.PIPE if capture_output else None)
        os.close(write_fd)
        write_fd = None
        spec = {'argv': argv, 'cwd': str(cwd), 'timeout': timeout,
                'allow_children': allow_children, 'controller_pid': os.getpid()}
        process.stdin.write(json.dumps(spec).encode() + b'\n')
        process.stdin.flush()
        if capture_output:
            for stream, tail in zip((process.stdout, process.stderr), tails):
                thread = threading.Thread(target=drain, args=(stream, tail), daemon=True)
                readers.append(thread)
                thread.start()
        deadline = time.monotonic() + timeout + 7
        signalled = False
        while process.poll() is None:
            if cancel is not None and cancel.is_set() and not signalled:
                process.terminate()
                signalled = True
            if time.monotonic() >= deadline:
                raise OSError('Supervisor exceeded command and cleanup deadline')
            time.sleep(.02)
        data = os.read(read_fd, 4096)
        report = json.loads(data) if data else {}
        if not report.get('cleanup_complete'):
            raise OSError('Descendant cleanup was not confirmed')
        if report.get('error') == 'timeout':
            raise subprocess.TimeoutExpired(argv, timeout)
        if report.get('error') == 'cancelled' or signalled:
            raise InterruptedError('Command cancelled')
        if report.get('error') or process.returncode != 0:
            raise OSError('Managed launch failed: ' + report.get('error', 'supervisor'))
        for thread in readers:
            thread.join(timeout=3)
        if any(thread.is_alive() for thread in readers):
            raise OSError('Output stream outlived descendant cleanup')
        return subprocess.CompletedProcess(argv, report['returncode'],
            bytes(tails[0]) if capture_output else None, bytes(tails[1]) if capture_output else None)
    finally:
        if write_fd is not None:
            os.close(write_fd)
        os.close(read_fd)
        if process:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=7)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            if process.stdin:
                process.stdin.close()
        for thread in readers:
            thread.join(timeout=3)
        if any(thread.is_alive() for thread in readers):
            raise OSError('Output stream outlived descendant cleanup')


if __name__ == '__main__':
    if sys.platform == 'linux' and len(sys.argv) == 3 and sys.argv[1] == '--linux-supervisor':
        _linux_supervise(int(sys.argv[2]))
    else:
        raise SystemExit('Internal process supervisor; import run_managed instead')

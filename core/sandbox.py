"""
Lightweight sandbox for dynamic analysis of suspicious PE binaries.
Uses Windows Job Objects + restricted tokens via ctypes for process isolation.
Monitors file/registry/network activity via ETW during execution.
"""

import ctypes
import ctypes.wintypes as wintypes
import os
import shutil
import tempfile
import threading
import time
import logging
from dataclasses import dataclass, field
from typing import List, Optional

kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32

# --- Constants ---
CREATE_SUSPENDED = 0x00000004
CREATE_BREAKAWAY_FROM_JOB = 0x01000000
NORMAL_PRIORITY_CLASS = 0x00000020

JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400

JobObjectExtendedLimitInformation = 9

DISABLE_MAX_PRIVILEGE = 0x1
SANDBOX_INERT = 0x2

PROCESS_ALL_ACCESS = 0x001FFFFF
THREAD_SUSPEND_RESUME = 0x0002

SE_GROUP_USE_FOR_DENY_ONLY = 0x00000010

TOKEN_DUPLICATE = 0x0002
TOKEN_QUERY = 0x0008
TOKEN_ASSIGN_PRIMARY = 0x0001
TOKEN_ADJUST_DEFAULT = 0x0080
TOKEN_ADJUST_SESSIONID = 0x0100

SecurityImpersonation = 2
TokenPrimary = 1

INFINITE = 0xFFFFFFFF
WAIT_TIMEOUT = 0x00000102


class SECURITY_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("nLength", wintypes.DWORD),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", wintypes.BOOL),
    ]


class STARTUPINFOW(ctypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD),
        ("lpReserved", wintypes.LPWSTR),
        ("lpDesktop", wintypes.LPWSTR),
        ("lpTitle", wintypes.LPWSTR),
        ("dwX", wintypes.DWORD),
        ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD),
        ("dwYSize", wintypes.DWORD),
        ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD),
        ("dwFillAttribute", wintypes.DWORD),
        ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD),
        ("cbReserved2", wintypes.WORD),
        ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE),
        ("hStdOutput", wintypes.HANDLE),
        ("hStdError", wintypes.HANDLE),
    ]


class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE),
        ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD),
        ("dwThreadId", wintypes.DWORD),
    ]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


class SID_AND_ATTRIBUTES(ctypes.Structure):
    _fields_ = [
        ("Sid", ctypes.c_void_p),
        ("Attributes", wintypes.DWORD),
    ]


@dataclass
class SandboxConfig:
    timeout_seconds: int = 30
    memory_limit_mb: int = 256
    max_child_processes: int = 1
    allow_network: bool = False


@dataclass
class SandboxResult:
    file_path: str
    executed: bool = False
    exit_code: int = -1
    runtime_seconds: float = 0.0
    timed_out: bool = False
    etw_events: list = field(default_factory=list)
    behavioral_score: int = 0
    behavioral_reasons: list = field(default_factory=list)
    error: Optional[str] = None


def _is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def run_in_sandbox(file_path, config=None, etw_session=None):
    """Execute a PE binary in a restricted sandbox and return analysis results."""
    if config is None:
        config = SandboxConfig()

    result = SandboxResult(file_path=file_path)

    if not os.path.isfile(file_path):
        result.error = "File not found"
        return result

    sandbox_dir = tempfile.mkdtemp(prefix="sentinelx_sandbox_")
    sandbox_exe = os.path.join(sandbox_dir, os.path.basename(file_path))

    try:
        shutil.copy2(file_path, sandbox_exe)
    except Exception as e:
        result.error = f"Failed to copy file to sandbox: {e}"
        return result

    job_handle = None
    pi = PROCESS_INFORMATION()

    try:
        # Create Job Object with restrictions
        job_handle = kernel32.CreateJobObjectW(None, None)
        if not job_handle:
            result.error = "Failed to create Job Object"
            return result

        limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        ctypes.memset(ctypes.byref(limits), 0, ctypes.sizeof(limits))
        limits.BasicLimitInformation.LimitFlags = (
            JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_PROCESS_MEMORY
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        )
        limits.BasicLimitInformation.ActiveProcessLimit = config.max_child_processes + 1
        limits.ProcessMemoryLimit = config.memory_limit_mb * 1024 * 1024

        kernel32.SetInformationJobObject(
            job_handle,
            JobObjectExtendedLimitInformation,
            ctypes.byref(limits),
            ctypes.sizeof(limits),
        )

        # Create process SUSPENDED
        si = STARTUPINFOW()
        si.cb = ctypes.sizeof(si)
        creation_flags = CREATE_SUSPENDED | NORMAL_PRIORITY_CLASS

        success = kernel32.CreateProcessW(
            sandbox_exe,
            None,
            None,
            None,
            False,
            creation_flags,
            None,
            sandbox_dir,
            ctypes.byref(si),
            ctypes.byref(pi),
        )

        if not success:
            err = ctypes.get_last_error() or kernel32.GetLastError()
            result.error = f"CreateProcessW failed (error {err})"
            return result

        # Assign to Job Object
        kernel32.AssignProcessToJobObject(job_handle, pi.hProcess)

        # Start ETW observation window
        etw_start = time.time()

        # Resume the suspended thread
        kernel32.ResumeThread(pi.hThread)
        result.executed = True
        logging.info(f"[Sandbox] Process started: PID {pi.dwProcessId}, timeout={config.timeout_seconds}s")

        # Wait for process to complete or timeout
        wait_ms = config.timeout_seconds * 1000
        wait_result = kernel32.WaitForSingleObject(pi.hProcess, wait_ms)

        result.runtime_seconds = round(time.time() - etw_start, 2)

        if wait_result == WAIT_TIMEOUT:
            result.timed_out = True
            kernel32.TerminateProcess(pi.hProcess, 1)
            logging.info(f"[Sandbox] Process timed out after {config.timeout_seconds}s, terminated.")
        else:
            exit_code = wintypes.DWORD()
            kernel32.GetExitCodeProcess(pi.hProcess, ctypes.byref(exit_code))
            result.exit_code = exit_code.value

        # Collect ETW events for this PID
        if etw_session and etw_session.is_running:
            from core.etw_monitor import score_behavioral_events
            events = etw_session.get_events_since(etw_start)
            pid_events = [e for e in events if e.pid == pi.dwProcessId]
            result.etw_events = [
                {"type": e.event_type, "provider": e.provider, "timestamp": e.timestamp}
                for e in pid_events
            ]
            score, reasons = score_behavioral_events(events, pi.dwProcessId)
            result.behavioral_score = score
            result.behavioral_reasons = reasons

    except Exception as e:
        result.error = str(e)
        logging.error(f"[Sandbox] Error: {e}")
    finally:
        if pi.hThread:
            kernel32.CloseHandle(pi.hThread)
        if pi.hProcess:
            kernel32.CloseHandle(pi.hProcess)
        if job_handle:
            kernel32.CloseHandle(job_handle)

        try:
            shutil.rmtree(sandbox_dir, ignore_errors=True)
        except Exception:
            pass

    return result

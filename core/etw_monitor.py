"""
ETW (Event Tracing for Windows) monitor via ctypes/advapi32.
Provides lightweight runtime behavioral monitoring for process, file, registry, and network events.
Requires Administrator privileges for kernel providers — gracefully degrades if not elevated.
"""

import ctypes
import ctypes.wintypes as wintypes
import threading
import logging
import time
import os
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

advapi32 = ctypes.windll.advapi32
kernel32 = ctypes.windll.kernel32

# --- ETW Constants ---
WNODE_FLAG_TRACED_GUID = 0x00020000
EVENT_TRACE_REAL_TIME_MODE = 0x00000100
EVENT_TRACE_FILE_MODE_NONE = 0x00000000
PROCESS_TRACE_MODE_REAL_TIME = 0x00000100
PROCESS_TRACE_MODE_EVENT_RECORD = 0x10000000
EVENT_CONTROL_CODE_ENABLE_PROVIDER = 1
EVENT_CONTROL_CODE_DISABLE_PROVIDER = 0
TRACE_LEVEL_INFORMATION = 4
TRACE_LEVEL_VERBOSE = 5

ERROR_SUCCESS = 0
ERROR_ALREADY_EXISTS = 183

MAX_EVENTS = 5000


@dataclass
class ETWEvent:
    timestamp: float
    pid: int
    event_type: str
    provider: str
    opcode: int = 0
    details: str = ""


def _is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_ulong),
        ("Data2", ctypes.c_ushort),
        ("Data3", ctypes.c_ushort),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    def __init__(self, s=None):
        super().__init__()
        if s:
            parts = s.strip("{}").split("-")
            self.Data1 = int(parts[0], 16)
            self.Data2 = int(parts[1], 16)
            self.Data3 = int(parts[2], 16)
            b = bytes.fromhex(parts[3] + parts[4])
            for i in range(8):
                self.Data4[i] = b[i]


KERNEL_PROCESS_GUID = GUID("{22FB2CD6-0E7B-422B-A0C7-2FAD1FD0E716}")
KERNEL_FILE_GUID = GUID("{EDD08927-9CC4-4E65-B970-C2560FB5C289}")
KERNEL_REGISTRY_GUID = GUID("{70EB4F03-C1DE-4F73-A051-33D13D5413BD}")
KERNEL_NETWORK_GUID = GUID("{7DD42A49-5329-4832-8DFD-43D979153A88}")


class WNODE_HEADER(ctypes.Structure):
    _fields_ = [
        ("BufferSize", ctypes.c_ulong),
        ("ProviderId", ctypes.c_ulong),
        ("HistoricalContext", ctypes.c_uint64),
        ("TimeStamp", ctypes.c_int64),
        ("Guid", GUID),
        ("ClientContext", ctypes.c_ulong),
        ("Flags", ctypes.c_ulong),
    ]


class EVENT_TRACE_PROPERTIES(ctypes.Structure):
    _fields_ = [
        ("Wnode", WNODE_HEADER),
        ("BufferSize", ctypes.c_ulong),
        ("MinimumBuffers", ctypes.c_ulong),
        ("MaximumBuffers", ctypes.c_ulong),
        ("MaximumFileSize", ctypes.c_ulong),
        ("LogFileMode", ctypes.c_ulong),
        ("FlushTimer", ctypes.c_ulong),
        ("EnableFlags", ctypes.c_ulong),
        ("AgeLimit", ctypes.c_long),
        ("NumberOfBuffers", ctypes.c_ulong),
        ("FreeBuffers", ctypes.c_ulong),
        ("EventsLost", ctypes.c_ulong),
        ("BuffersWritten", ctypes.c_ulong),
        ("LogBuffersLost", ctypes.c_ulong),
        ("RealTimeBuffersLost", ctypes.c_ulong),
        ("LoggerThreadId", ctypes.c_void_p),
        ("LogFileNameOffset", ctypes.c_ulong),
        ("LoggerNameOffset", ctypes.c_ulong),
    ]


class EVENT_HEADER(ctypes.Structure):
    _fields_ = [
        ("Size", ctypes.c_ushort),
        ("HeaderType", ctypes.c_ushort),
        ("Flags", ctypes.c_ushort),
        ("EventProperty", ctypes.c_ushort),
        ("ThreadId", ctypes.c_ulong),
        ("ProcessId", ctypes.c_ulong),
        ("TimeStamp", ctypes.c_int64),
        ("ProviderId", GUID),
        ("EventDescriptor_Id", ctypes.c_ushort),
        ("EventDescriptor_Version", ctypes.c_ubyte),
        ("EventDescriptor_Channel", ctypes.c_ubyte),
        ("EventDescriptor_Level", ctypes.c_ubyte),
        ("EventDescriptor_Opcode", ctypes.c_ubyte),
        ("EventDescriptor_Task", ctypes.c_ushort),
        ("EventDescriptor_Keyword", ctypes.c_uint64),
        ("KernelTime", ctypes.c_ulong),
        ("UserTime", ctypes.c_ulong),
        ("ActivityId", GUID),
    ]


class ETW_BUFFER_CONTEXT(ctypes.Structure):
    _fields_ = [
        ("ProcessorNumber", ctypes.c_ubyte),
        ("Alignment", ctypes.c_ubyte),
        ("LoggerId", ctypes.c_ushort),
    ]


class EVENT_RECORD(ctypes.Structure):
    _fields_ = [
        ("EventHeader", EVENT_HEADER),
        ("BufferContext", ETW_BUFFER_CONTEXT),
        ("ExtendedDataCount", ctypes.c_ushort),
        ("UserDataLength", ctypes.c_ushort),
        ("ExtendedData", ctypes.c_void_p),
        ("UserData", ctypes.c_void_p),
        ("UserContext", ctypes.c_void_p),
    ]


class EVENT_TRACE_LOGFILEW(ctypes.Structure):
    _fields_ = [
        ("LogFileName", ctypes.c_wchar_p),
        ("LoggerName", ctypes.c_wchar_p),
        ("CurrentTime", ctypes.c_int64),
        ("BuffersRead", ctypes.c_ulong),
        ("LogFileMode_union", ctypes.c_ulong),
        ("CurrentEvent", ctypes.c_void_p),
        ("LogfileHeader", ctypes.c_byte * 280),
        ("BufferCallback", ctypes.c_void_p),
        ("BufferSize", ctypes.c_ulong),
        ("Filled", ctypes.c_ulong),
        ("EventsLost", ctypes.c_ulong),
        ("EventRecordCallback", ctypes.c_void_p),
        ("IsKernelTrace", ctypes.c_ulong),
        ("Context", ctypes.c_void_p),
    ]


EVENT_RECORD_CALLBACK = ctypes.CFUNCTYPE(None, ctypes.POINTER(EVENT_RECORD))

# Map opcode numbers to human-readable event types
PROCESS_OPCODES = {1: "ProcessStart", 2: "ProcessStop", 3: "ThreadStart", 4: "ThreadStop"}
FILE_OPCODES = {0: "FileCreate", 32: "FileCreate", 35: "FileDelete", 36: "FileRename"}
REGISTRY_OPCODES = {1: "RegCreate", 2: "RegOpen", 3: "RegDelete", 5: "RegSetValue", 6: "RegDeleteValue"}
NETWORK_OPCODES = {10: "TcpSend", 11: "TcpRecv", 12: "TcpConnect", 13: "TcpDisconnect", 15: "TcpAccept"}


class ETWSession:
    """Manages a single ETW trace session with multiple providers."""

    SESSION_NAME = "SentinelX_ETW_Session"
    PROP_BUF_SIZE = ctypes.sizeof(EVENT_TRACE_PROPERTIES) + 512

    def __init__(self):
        self.is_running = False
        self._session_handle = ctypes.c_uint64(0)
        self._trace_handle = ctypes.c_uint64(0)
        self._events = deque(maxlen=MAX_EVENTS)
        self._lock = threading.Lock()
        self._consumer_thread: Optional[threading.Thread] = None
        self._callback_ref = None

    @property
    def events(self):
        with self._lock:
            return list(self._events)

    def get_events_since(self, since_ts):
        with self._lock:
            return [e for e in self._events if e.timestamp > since_ts]

    def clear_events(self):
        with self._lock:
            self._events.clear()

    def start(self):
        if self.is_running:
            return True

        if not _is_admin():
            logging.warning("ETW monitor requires Administrator privileges. Skipping.")
            return False

        try:
            self._stop_existing_session()
            if not self._start_trace_session():
                return False
            self._enable_providers()
            self._start_consumer()
            self.is_running = True
            logging.info("ETW session started successfully.")
            return True
        except Exception as e:
            logging.error(f"Failed to start ETW session: {e}")
            self.stop()
            return False

    def stop(self):
        if not self.is_running and self._session_handle.value == 0:
            return

        self.is_running = False

        try:
            self._disable_providers()
        except Exception:
            pass

        try:
            self._stop_trace_session()
        except Exception:
            pass

        if self._consumer_thread and self._consumer_thread.is_alive():
            self._consumer_thread.join(timeout=5)

        self._session_handle = ctypes.c_uint64(0)
        logging.info("ETW session stopped.")

    def _stop_existing_session(self):
        buf = (ctypes.c_byte * self.PROP_BUF_SIZE)()
        props = ctypes.cast(buf, ctypes.POINTER(EVENT_TRACE_PROPERTIES))
        props.contents.Wnode.BufferSize = self.PROP_BUF_SIZE
        props.contents.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
        advapi32.ControlTraceW(
            ctypes.c_uint64(0),
            self.SESSION_NAME,
            props,
            1,  # EVENT_TRACE_CONTROL_STOP
        )

    def _start_trace_session(self):
        buf = (ctypes.c_byte * self.PROP_BUF_SIZE)()
        ctypes.memset(buf, 0, self.PROP_BUF_SIZE)
        props = ctypes.cast(buf, ctypes.POINTER(EVENT_TRACE_PROPERTIES))
        props.contents.Wnode.BufferSize = self.PROP_BUF_SIZE
        props.contents.Wnode.Flags = WNODE_FLAG_TRACED_GUID
        props.contents.Wnode.ClientContext = 1  # QPC
        props.contents.BufferSize = 64  # KB
        props.contents.MinimumBuffers = 4
        props.contents.MaximumBuffers = 16
        props.contents.LogFileMode = EVENT_TRACE_REAL_TIME_MODE
        props.contents.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
        self._props_buf = buf

        session_handle = ctypes.c_uint64(0)
        status = advapi32.StartTraceW(
            ctypes.byref(session_handle),
            self.SESSION_NAME,
            props,
        )
        if status != ERROR_SUCCESS:
            logging.error(f"StartTraceW failed with error {status}")
            return False

        self._session_handle = session_handle
        return True

    def _enable_providers(self):
        providers = [
            (KERNEL_PROCESS_GUID, 0x10),  # PROCESS_EVENT keyword
            (KERNEL_FILE_GUID, 0x10),
            (KERNEL_REGISTRY_GUID, 0x10),
            (KERNEL_NETWORK_GUID, 0x10),
        ]
        for guid, keywords in providers:
            status = advapi32.EnableTraceEx2(
                self._session_handle,
                ctypes.byref(guid),
                EVENT_CONTROL_CODE_ENABLE_PROVIDER,
                TRACE_LEVEL_INFORMATION,
                ctypes.c_uint64(keywords),
                ctypes.c_uint64(0),
                0,
                None,
            )
            if status != ERROR_SUCCESS:
                logging.warning(f"EnableTraceEx2 for provider failed (status={status}), may be unsupported.")

    def _disable_providers(self):
        providers = [KERNEL_PROCESS_GUID, KERNEL_FILE_GUID, KERNEL_REGISTRY_GUID, KERNEL_NETWORK_GUID]
        for guid in providers:
            advapi32.EnableTraceEx2(
                self._session_handle,
                ctypes.byref(guid),
                EVENT_CONTROL_CODE_DISABLE_PROVIDER,
                0, ctypes.c_uint64(0), ctypes.c_uint64(0), 0, None,
            )

    def _stop_trace_session(self):
        buf = (ctypes.c_byte * self.PROP_BUF_SIZE)()
        props = ctypes.cast(buf, ctypes.POINTER(EVENT_TRACE_PROPERTIES))
        props.contents.Wnode.BufferSize = self.PROP_BUF_SIZE
        props.contents.LoggerNameOffset = ctypes.sizeof(EVENT_TRACE_PROPERTIES)
        advapi32.ControlTraceW(
            self._session_handle,
            None,
            props,
            1,  # STOP
        )

    def _start_consumer(self):
        def _event_callback(event_record_ptr):
            try:
                er = event_record_ptr.contents
                pid = er.EventHeader.ProcessId
                opcode = er.EventHeader.EventDescriptor_Opcode
                provider_guid = er.EventHeader.ProviderId

                provider_name, event_type = self._classify_event(provider_guid, opcode)
                if not event_type:
                    return

                evt = ETWEvent(
                    timestamp=time.time(),
                    pid=pid,
                    event_type=event_type,
                    provider=provider_name,
                    opcode=opcode,
                )
                with self._lock:
                    self._events.append(evt)
            except Exception:
                pass

        self._callback_ref = EVENT_RECORD_CALLBACK(_event_callback)

        def _consumer_worker():
            logfile = EVENT_TRACE_LOGFILEW()
            ctypes.memset(ctypes.byref(logfile), 0, ctypes.sizeof(logfile))
            logfile.LoggerName = self.SESSION_NAME
            logfile.LogFileMode_union = PROCESS_TRACE_MODE_REAL_TIME | PROCESS_TRACE_MODE_EVENT_RECORD
            logfile.EventRecordCallback = ctypes.cast(self._callback_ref, ctypes.c_void_p)

            trace_handle = advapi32.OpenTraceW(ctypes.byref(logfile))
            INVALID = 0xFFFFFFFFFFFFFFFF
            if trace_handle == INVALID:
                logging.error("OpenTraceW failed for ETW consumer.")
                return

            self._trace_handle = ctypes.c_uint64(trace_handle)
            advapi32.ProcessTrace(
                ctypes.byref(self._trace_handle), 1, None, None,
            )

        self._consumer_thread = threading.Thread(target=_consumer_worker, daemon=True, name="ETW-Consumer")
        self._consumer_thread.start()

    @staticmethod
    def _classify_event(guid, opcode):
        g1 = guid.Data1
        if g1 == KERNEL_PROCESS_GUID.Data1:
            return ("Process", PROCESS_OPCODES.get(opcode, f"ProcessOp_{opcode}"))
        elif g1 == KERNEL_FILE_GUID.Data1:
            return ("File", FILE_OPCODES.get(opcode))
        elif g1 == KERNEL_REGISTRY_GUID.Data1:
            return ("Registry", REGISTRY_OPCODES.get(opcode))
        elif g1 == KERNEL_NETWORK_GUID.Data1:
            return ("Network", NETWORK_OPCODES.get(opcode))
        return (None, None)


def score_behavioral_events(events, target_pid):
    """Score the behavioral events for a specific PID. Returns (score, reasons)."""
    score = 0
    reasons = []
    pid_events = [e for e in events if e.pid == target_pid]

    file_creates = sum(1 for e in pid_events if e.event_type == "FileCreate")
    file_deletes = sum(1 for e in pid_events if e.event_type == "FileDelete")
    reg_writes = sum(1 for e in pid_events if e.event_type in ("RegSetValue", "RegCreate"))
    net_connects = sum(1 for e in pid_events if e.event_type in ("TcpConnect", "TcpSend"))
    child_procs = sum(1 for e in pid_events if e.event_type == "ProcessStart")

    if file_creates > 50:
        score += 40
        reasons.append(f"Mass file creation ({file_creates})")
    if file_deletes > 20:
        score += 30
        reasons.append(f"Mass file deletion ({file_deletes})")
    if reg_writes > 5:
        score += 25
        reasons.append(f"Registry modifications ({reg_writes})")
    if net_connects > 3:
        score += 30
        reasons.append(f"Network connections ({net_connects})")
    if child_procs > 2:
        score += 20
        reasons.append(f"Child process spawning ({child_procs})")

    return score, reasons

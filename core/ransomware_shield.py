"""
Real-time Anti-Ransomware Shield for SentinelX.
Three detection layers: canary files, mass-modification counter, VSS deletion watcher.
All detection runs in daemon threads — never blocks the Qt main thread.
"""

import os
import hashlib
import threading
import time
import logging
import psutil
from collections import deque

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler

from core.ransomware_engine import RANSOMWARE_EXTENSIONS

PROTECTED_EXTENSIONS = {
    '.doc', '.docx', '.xls', '.xlsx', '.pdf', '.txt', '.ppt', '.pptx',
    '.jpg', '.jpeg', '.png', '.mp4', '.avi', '.mov', '.zip', '.rar',
    '.csv', '.odt', '.rtf', '.bmp', '.gif', '.mp3', '.wav',
}

CANARY_FILENAME = '!SentinelX_Canary_do_not_delete.txt'
CANARY_CONTENT = (
    'SentinelX Antivirus Protection File\n'
    'This file is a security sentinel. Do not delete or modify it.\n'
    'It detects ransomware activity on your system.\n'
) * 8

SYSTEM_PROCESS_NAMES = {
    'system', 'registry', 'smss.exe', 'csrss.exe', 'wininit.exe',
    'services.exe', 'lsass.exe', 'svchost.exe', 'winlogon.exe',
    'explorer.exe', 'dwm.exe', 'taskhostw.exe',
}

VSS_SIGNATURES = [
    'vssadmin delete shadows',
    'shadowcopy delete',
    'bcdedit /set',
    'wbadmin delete catalog',
    'resize shadowstorage',
    'delete shadows /all',
]


class _ShieldHandler(FileSystemEventHandler):
    def __init__(self, shield: 'RansomwareShield'):
        super().__init__()
        self._shield = shield

    def on_modified(self, event):
        if event.is_directory:
            return
        path = os.path.normcase(event.src_path)

        # Canary file touched — immediate response, highest confidence
        if path in self._shield._canary_hashes:
            self._shield._on_canary_triggered(event.src_path)
            return

        ext = os.path.splitext(path)[1].lower()
        if ext in PROTECTED_EXTENSIONS:
            self._shield._record_modification()

    def on_moved(self, event):
        if event.is_directory:
            return
        new_ext = os.path.splitext(event.dest_path)[1].lower()
        if new_ext in RANSOMWARE_EXTENSIONS:
            self._shield._trigger_response(
                'extension_rename',
                f"File renamed to known ransomware extension: {os.path.basename(event.dest_path)}"
            )


class RansomwareShield:
    DETECTION_THRESHOLD = 20   # protected-file modifications
    DETECTION_WINDOW = 60      # sliding window in seconds

    def __init__(self):
        self.is_running = False
        self._lock = threading.Lock()
        self._events: deque = deque()
        self._observer: Observer | None = None
        self._vss_thread: threading.Thread | None = None
        self._canary_hashes: dict[str, str] = {}
        self._pending_alerts: deque = deque(maxlen=50)

    # ── Public API ────────────────────────────────────────────────────────────

    def start(self):
        if self.is_running:
            return
        self._deploy_canaries()
        self._start_watchdog()
        self._start_vss_watcher()
        self.is_running = True
        logging.info("Anti-Ransomware Shield started.")

    def stop(self):
        self.is_running = False
        if self._observer:
            try:
                self._observer.stop()
                self._observer.join(timeout=5)
            except Exception:
                pass
            self._observer = None
        logging.info("Anti-Ransomware Shield stopped.")

    def pop_alerts(self) -> list:
        """Drain and return all pending alerts (called by UI timer — safe from any thread)."""
        alerts = []
        try:
            while True:
                alerts.append(self._pending_alerts.popleft())
        except IndexError:
            pass
        return alerts

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _get_protected_dirs(self) -> list:
        home = os.path.expanduser('~')
        dirs = []
        for name in ('Desktop', 'Documents', 'Downloads', 'Pictures', 'Videos'):
            path = os.path.join(home, name)
            if os.path.isdir(path):
                dirs.append(path)
        return dirs

    def _deploy_canaries(self):
        """Write a canary file to each protected directory and hash it."""
        for d in self._get_protected_dirs():
            path = os.path.join(d, CANARY_FILENAME)
            try:
                if not os.path.exists(path):
                    with open(path, 'w', encoding='utf-8') as f:
                        f.write(CANARY_CONTENT)
                with open(path, 'rb') as f:
                    digest = hashlib.sha256(f.read()).hexdigest()
                self._canary_hashes[os.path.normcase(path)] = digest
                logging.info(f"Canary deployed: {path}")
            except Exception as e:
                logging.warning(f"Could not deploy canary to {d}: {e}")

    def _start_watchdog(self):
        handler = _ShieldHandler(self)
        self._observer = Observer()
        for d in self._get_protected_dirs():
            self._observer.schedule(handler, d, recursive=True)
        self._observer.start()

    def _start_vss_watcher(self):
        def _loop():
            try:
                import pythoncom
                import wmi
                pythoncom.CoInitialize()
                c = wmi.WMI()
                watcher = c.Win32_Process.watch_for('creation')
                while self.is_running:
                    try:
                        proc = watcher(timeout_ms=2000)
                        if proc:
                            cmd = (getattr(proc, 'CommandLine', '') or '').lower()
                            for sig in VSS_SIGNATURES:
                                if sig in cmd:
                                    self._trigger_response(
                                        'vss_deletion',
                                        f"Shadow copy deletion attempt: {cmd[:100]}"
                                    )
                                    break
                    except Exception:
                        pass
            except Exception as e:
                logging.error(f"[RansomwareShield] VSS watcher error: {e}")
            finally:
                try:
                    import pythoncom
                    pythoncom.CoUninitialize()
                except Exception:
                    pass

        self._vss_thread = threading.Thread(
            target=_loop, daemon=True, name='RW-VSS-Watcher'
        )
        self._vss_thread.start()

    def _record_modification(self):
        """Add an event to the sliding window; trigger if threshold exceeded."""
        with self._lock:
            now = time.time()
            self._events.append(now)
            cutoff = now - self.DETECTION_WINDOW
            while self._events and self._events[0] < cutoff:
                self._events.popleft()
            count = len(self._events)

        if count >= self.DETECTION_THRESHOLD:
            with self._lock:
                self._events.clear()   # reset so we don't re-fire on every subsequent event
            self._trigger_response(
                'mass_modification',
                f"Mass file modification: {count} protected files modified in {self.DETECTION_WINDOW}s"
            )

    def _on_canary_triggered(self, path: str):
        self._trigger_response(
            'canary',
            f"Canary file modified — ransomware activity detected: {os.path.basename(path)}"
        )

    def _trigger_response(self, kind: str, reason: str):
        logging.warning(f"[RansomwareShield] THREAT: {reason}")
        pid, proc_name = self._find_suspicious_process()
        if pid:
            try:
                p = psutil.Process(pid)
                p.terminate()
                p.wait(timeout=3)
                alert = f"{reason}\nProcess terminated: {proc_name} (PID {pid})"
                logging.warning(f"[RansomwareShield] Killed PID {pid} ({proc_name})")
            except Exception as e:
                alert = f"{reason}\nCould not terminate process: {e}"
                logging.error(f"[RansomwareShield] Kill failed: {e}")
        else:
            alert = f"{reason}\n(Offending process could not be identified)"

        self._pending_alerts.append(alert)

    def _find_suspicious_process(self) -> tuple[int | None, str]:
        """
        Identify the process with the highest disk write rate over a short sample.
        Excludes system processes and SentinelX itself.
        """
        my_pid = os.getpid()
        snapshots: dict[int, tuple[str, int]] = {}

        try:
            for proc in psutil.process_iter(['pid', 'name']):
                pid = proc.pid
                name = (proc.info.get('name') or '').lower()
                if pid <= 4 or pid == my_pid or name in SYSTEM_PROCESS_NAMES:
                    continue
                try:
                    snapshots[pid] = (proc.info['name'], proc.io_counters().write_bytes)
                except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                    pass

            time.sleep(0.15)

            best_pid, best_name, best_delta = None, '', 0
            for pid, (name, before) in snapshots.items():
                try:
                    after = psutil.Process(pid).io_counters().write_bytes
                    delta = after - before
                    if delta > best_delta:
                        best_delta = delta
                        best_pid = pid
                        best_name = name
                except (psutil.AccessDenied, psutil.NoSuchProcess, AttributeError):
                    pass

            return best_pid, best_name
        except Exception as e:
            logging.error(f"[RansomwareShield] Process detection error: {e}")
            return None, ''

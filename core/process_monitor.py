import wmi
import threading
import logging
import psutil
import os
import sys
import pythoncom
from core import engine_registry


class ProcessMonitor:
    def __init__(self, scanner=None, yara_engine=None, target_directory=None):
        self.target_directory = target_directory.lower() if target_directory else None
        self.scanner = scanner or engine_registry.get_scanner()
        self.yara_engine = yara_engine or engine_registry.get_yara_engine()
        self.quarantine_mgr = engine_registry.get_quarantine_manager()
        self.etw_session = None
        self.is_running = False
        self.thread = None

    def start(self):
        self.is_running = True
        self.thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self.thread.start()
        logging.info("Real-Time Process Execution Monitoring started.")

    def stop(self):
        self.is_running = False
        logging.info("Real-Time Process Execution Monitoring stopped.")

    def _monitor_loop(self):
        try:
            pythoncom.CoInitialize()
            c = wmi.WMI()
            process_watcher = c.Win32_Process.watch_for("creation")

            while self.is_running:
                try:
                    new_process = process_watcher(timeout_ms=2000)
                    if not new_process:
                        continue

                    exe_path = new_process.ExecutablePath
                    if not exe_path:
                        continue

                    exe_lower = exe_path.lower()

                    if int(new_process.ProcessId) == os.getpid():
                        continue

                    if exe_lower == sys.executable.lower() or exe_lower.endswith('\\sentinelx.exe'):
                        continue

                    if exe_lower.startswith("c:\\windows\\") or exe_lower.startswith("c:\\program files"):
                        continue

                    cmd_line = getattr(new_process, "CommandLine", exe_path)
                    if not cmd_line:
                        cmd_line = exe_path

                    logging.info(f"[LIVE BEHAVIOR FEED] Launch: {cmd_line} (PID: {new_process.ProcessId})")
                    self._scan_and_terminate(exe_path, int(new_process.ProcessId), cmd_line)

                except wmi.x_wmi_timed_out:
                    continue
                except Exception as e:
                    logging.error(f"Error in process watcher loop: {e}")

        except Exception as e:
            logging.error(f"Failed to start WMI Process Watcher: {e}")
        finally:
            pythoncom.CoUninitialize()

    def _scan_and_terminate(self, file_path, pid, cmd_line=""):
        try:
            if not os.path.exists(file_path):
                return

            yara_matches = self.yara_engine.scan_file(file_path)
            res = self.scanner.scan_file(file_path)
            res = self.scanner.evaluate_threat(res, yara_matches, None)
            threat_name = res.get('threat_level', 'Clean')

            if threat_name.startswith("Malicious"):
                self._kill_and_quarantine(file_path, pid, cmd_line, res, threat_name)

        except Exception as e:
            logging.error(f"Error scanning launched process {file_path}: {e}")

    def _kill_and_quarantine(self, file_path, pid, cmd_line, res, threat_name):
        logging.warning(f"THREAT EXECUTED! Terminating PID {pid}: {cmd_line}")
        try:
            p = psutil.Process(pid)
            p.terminate()
            p.wait(timeout=3)
            logging.info(f"Successfully killed malicious process PID {pid}")
        except Exception as e:
            logging.error(f"Failed to kill process {pid}: {e}")

        file_hash = res.get('hashes', {}).get('md5', 'unknown')
        self.quarantine_mgr.quarantine_file(file_path, threat_name, file_hash)

import wmi
import threading
import logging
import psutil
import os
import pythoncom
from core.scanner import CoreScanner
from core.yara_engine import YaraEngine
from core.quarantine import QuarantineManager

class ProcessMonitor:
    def __init__(self, target_directory="J:\\SentinelX_Test"):
        self.target_directory = target_directory.lower()
        self.scanner = CoreScanner()
        self.yara_engine = YaraEngine()
        self.quarantine_mgr = QuarantineManager()
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
            # Initialize WMI to hook into Windows Process Creation Events
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
                    
                    # Ignore common Windows system directories to avoid locking the OS
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
        """Scans the executable that was just launched. If malicious, kill it."""
        try:
            if not os.path.exists(file_path):
                return

            # Check YARA first for speed
            yara_matches = self.yara_engine.scan_file(file_path)
            
            # Check Heuristics
            res = self.scanner.scan_file(file_path)
            
            threat_name = "Clean"
            if yara_matches:
                threat_name = f"Malicious ({', '.join(yara_matches)})"
            elif res.get('threat_level') != "Clean":
                threat_name = res.get('threat_level')

            if threat_name != "Clean":
                logging.warning(f"THREAT EXECUTED! Terminating PID {pid}: {cmd_line}")
                
                # 1. Kill the Process
                try:
                    p = psutil.Process(pid)
                    p.terminate()
                    p.wait(timeout=3)
                    logging.info(f"Successfully killed malicious process PID {pid}")
                except Exception as e:
                    logging.error(f"Failed to kill process {pid}: {e}")

                # 2. Quarantine the executable
                file_hash = res.get('hashes', {}).get('md5', 'unknown')
                self.quarantine_mgr.quarantine_file(file_path, threat_name, file_hash)

        except Exception as e:
            logging.error(f"Error scanning launched process {file_path}: {e}")

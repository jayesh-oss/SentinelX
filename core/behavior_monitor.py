import time
import os
import threading
import logging
import threading
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from core.scanner import CoreScanner
from core.yara_engine import YaraEngine
from core.quarantine import QuarantineManager

class SentinelEventHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.scanner = CoreScanner()
        self.yara_engine = YaraEngine()
        self.quarantine_mgr = QuarantineManager()
        self.scan_lock = threading.Lock()
        self.last_scanned = {}
        # Monitor files, but we will force non-executables to 'Clean' later
        self.monitored_extensions = {'.exe', '.dll', '.bat', '.ps1', '.vbs', '.cmd', '.pdf', '.doc', '.docx', '.xls', '.xlsx'}

    def is_target_file(self, file_path):
        ext = os.path.splitext(file_path)[1].lower()
        return ext in self.monitored_extensions

    def on_created(self, event):
        if not event.is_directory and self.is_target_file(event.src_path):
            self.process_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory and self.is_target_file(event.src_path):
            self.process_file(event.src_path)

    def process_file(self, file_path):
        """Scans the file in a separate thread to avoid blocking Watchdog."""
        
        # Debounce rapid overlapping watchdog events
        with self.scan_lock:
            current_time = time.time()
            if file_path in self.last_scanned:
                if current_time - self.last_scanned[file_path] < 3.0:
                    return # Skip if we scanned this exact file within the last 3 seconds
            self.last_scanned[file_path] = current_time

        def scan_worker():
            try:
                # Wait briefly for file to be completely written to disk
                time.sleep(1.0)
                if not os.path.exists(file_path):
                    return

                # Re-verify lock isn't held by OS
                try:
                    with open(file_path, 'a'): pass
                except IOError:
                    # File is currently locked by the writer process, delay and try again
                    time.sleep(2.0)
                    
                logging.info(f"Real-Time Monitor scanning: {file_path}")
                
                # Check YARA first for speed
                yara_matches = self.yara_engine.scan_file(file_path)
                
                # Check Heuristics & Static Analysis
                res = self.scanner.scan_file(file_path)
                
                # Evaluate Unified Threat Score (Real-time omits VT to avoid API rate limits)
                res = self.scanner.evaluate_threat(res, yara_matches, None)
                threat_name = res.get('threat_level', 'Clean')

                if threat_name != "Clean":
                    logging.warning(f"THREAT DETECTED by Real-Time Protection: {file_path}")
                    # Quarantine immediately
                    file_hash = res.get('hashes', {}).get('md5', 'unknown')
                    self.quarantine_mgr.quarantine_file(file_path, threat_name, file_hash)

            except Exception as e:
                logging.error(f"Error in real-time scanning file {file_path}: {e}")

        threading.Thread(target=scan_worker, daemon=True).start()

class BehaviorMonitor:
    def __init__(self, target_directory="J:\\SentinelX_Test"):
        self.target_directory = target_directory
        self.event_handler = SentinelEventHandler()
        self.is_running = False

    def start(self):
        if not os.path.exists(self.target_directory):
            try:
                os.makedirs(self.target_directory, exist_ok=True)
            except Exception:
                pass # Fallback gracefully
                return

        # Observers can only be started once, so we instantiate a new one each time
        self.observer = Observer()
        self.observer.schedule(self.event_handler, self.target_directory, recursive=True)
        self.observer.start()
        self.is_running = True
        logging.info(f"Real-Time Protection started. Monitoring: {self.target_directory}")

    def stop(self):
        if self.is_running and hasattr(self, 'observer'):
            self.observer.stop()
            self.observer.join()
            self.is_running = False
            logging.info("Real-Time Protection stopped.")

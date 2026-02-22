import time
import os
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

    def on_created(self, event):
        if not event.is_directory:
            self.process_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            self.process_file(event.src_path)

    def process_file(self, file_path):
        """Scans the file in a separate thread to avoid blocking Watchdog."""
        # Simple debounce or wait for file write lock to release
        def scan_worker():
            try:
                # Wait briefly for file to be completely written
                time.sleep(1.0)
                if not os.path.exists(file_path):
                    return

                logging.info(f"Real-Time Monitor scanning: {file_path}")
                
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
        self.observer = Observer()
        self.event_handler = SentinelEventHandler()
        self.is_running = False

    def start(self):
        if not os.path.exists(self.target_directory):
            try:
                os.makedirs(self.target_directory, exist_ok=True)
            except Exception:
                pass # Fallback gracefully
                return

        self.observer.schedule(self.event_handler, self.target_directory, recursive=True)
        self.observer.start()
        self.is_running = True
        logging.info(f"Real-Time Protection started. Monitoring: {self.target_directory}")

    def stop(self):
        if self.is_running:
            self.observer.stop()
            self.observer.join()
            self.is_running = False
            logging.info("Real-Time Protection stopped.")

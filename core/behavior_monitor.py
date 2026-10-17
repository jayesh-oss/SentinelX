import time
import os
import threading
import logging
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from core import engine_registry


class SentinelEventHandler(FileSystemEventHandler):
    def __init__(self):
        super().__init__()
        self.scanner = engine_registry.get_scanner()
        self.yara_engine = engine_registry.get_yara_engine()
        self.quarantine_mgr = engine_registry.get_quarantine_manager()
        self.scan_lock = threading.Lock()
        self.last_scanned = {}
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
        with self.scan_lock:
            current_time = time.time()
            if file_path in self.last_scanned:
                if current_time - self.last_scanned[file_path] < 3.0:
                    return
            self.last_scanned[file_path] = current_time

        def scan_worker():
            try:
                time.sleep(1.0)
                if not os.path.exists(file_path):
                    return

                try:
                    with open(file_path, 'a'):
                        pass
                except IOError:
                    time.sleep(2.0)

                logging.info(f"Real-Time Monitor scanning: {file_path}")

                yara_matches = self.yara_engine.scan_file(file_path)
                res = self.scanner.scan_file(file_path)
                res = self.scanner.evaluate_threat(res, yara_matches, None)
                threat_name = res.get('threat_level', 'Clean')

                if threat_name != "Clean":
                    logging.warning(f"THREAT DETECTED by Real-Time Protection: {file_path}")
                    file_hash = res.get('hashes', {}).get('md5', 'unknown')
                    self.quarantine_mgr.quarantine_file(file_path, threat_name, file_hash)

            except Exception as e:
                logging.error(f"Error in real-time scanning file {file_path}: {e}")

        threading.Thread(target=scan_worker, daemon=True).start()


class BehaviorMonitor:
    def __init__(self, target_directory=None):
        self.target_directory = target_directory
        self.event_handler = SentinelEventHandler()
        self.is_running = False

    def start(self):
        if not self.target_directory:
            logging.warning("BehaviorMonitor: no target directory set — monitoring not started.")
            return
        if not os.path.exists(self.target_directory):
            try:
                os.makedirs(self.target_directory, exist_ok=True)
            except Exception:
                return

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

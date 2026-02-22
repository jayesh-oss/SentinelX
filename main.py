import sys
import os
import logging
from PySide6.QtWidgets import QApplication
from ui.main_window import MainWindow

# Core imports to ensure engines initialize (optional here depending on where we instantiate them)
from core.scanner import CoreScanner
from core.yara_engine import YaraEngine
from database.db_manager import DatabaseManager
from core.behavior_monitor import BehaviorMonitor
from core.process_monitor import ProcessMonitor

def setup_environment():
    """Ensure all required directories exist before starting."""
    dirs = ['rules', 'quarantine', 'logs', 'database']
    for d in dirs:
        os.makedirs(d, exist_ok=True)

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
        handlers=[
            logging.FileHandler("logs/sentinelx.log"),
            logging.StreamHandler(sys.stdout)
        ]
    )

def load_stylesheet():
    style_path = os.path.join("ui", "styles", "dark_theme.qss")
    try:
        with open(style_path, "r") as f:
            return f.read()
    except Exception as e:
        logging.error(f"Failed to load stylesheet: {e}")
        return ""

def main():
    setup_environment()
    setup_logging()
    logging.info("Starting SentinelX Antivirus Engine...")

    # Initialize Backend Engines
    db = DatabaseManager(db_path="database/sentinelx.db")
    yara_engine = YaraEngine(rules_dir="rules")
    scanner = CoreScanner()

    # Start Real-Time Protection
    monitor = BehaviorMonitor(target_directory="J:\\SentinelX_Test")
    monitor.start()
    
    # Start Active Process Execution Execution Protection
    process_monitor = ProcessMonitor(target_directory="J:\\SentinelX_Test")
    process_monitor.start()

    # Initialize Frontend (GUI)
    app = QApplication(sys.argv)
    
    # Set application-wide font for consistency
    font = app.font()
    font.setFamily("Segoe UI")
    app.setFont(font)
    
    app.setStyleSheet(load_stylesheet())

    window = MainWindow()
    window.show()

    # Example of wiring signals to slots
    # window.scanner_tab.btn_scan.clicked.connect(scanner.scan_file)

    sys.exit(app.exec())

if __name__ == "__main__":
    main()

import sys
import os
import ctypes
import logging
from PySide6.QtWidgets import QApplication
from ui.main_window import MainWindow

from core import engine_registry
from core.behavior_monitor import BehaviorMonitor
from core.process_monitor import ProcessMonitor
from core.etw_monitor import ETWSession


def ensure_admin():
    """Re-launch as Administrator if not already elevated."""
    try:
        if ctypes.windll.shell32.IsUserAnAdmin():
            return True
    except Exception:
        return False

    # Re-run the script with elevation
    script = os.path.abspath(sys.argv[0])
    params = " ".join(f'"{a}"' for a in sys.argv[1:])
    ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, f'"{script}" {params}', None, 1
    )
    sys.exit(0)

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

    try:
        # Initialize Backend Engines via shared registry
        engine_registry.get_db()
        engine_registry.get_yara_engine()
        engine_registry.get_scanner()

        # Start Real-Time Protection
        monitor = BehaviorMonitor(target_directory="J:\\SentinelX_Test")
        monitor.start()

        # Initialize ETW session (off by default, user enables via dashboard)
        etw_session = ETWSession()

        # Start Active Process Execution Protection
        process_monitor = ProcessMonitor(target_directory="J:\\SentinelX_Test")
        process_monitor.set_etw_session(etw_session)
        process_monitor.start()

        # Initialize Frontend (GUI)
        app = QApplication(sys.argv)

        # Set application-wide font for consistency
        font = app.font()
        font.setFamily("Segoe UI")
        app.setFont(font)

        app.setStyleSheet(load_stylesheet())

        window = MainWindow(monitor, process_monitor, etw_session)
        window.show()

        sys.exit(app.exec())
    except Exception as e:
        import traceback
        logging.error(f"FATAL ERROR ON STARTUP: {e}")
        logging.error(traceback.format_exc())

if __name__ == "__main__":
    ensure_admin()
    main()

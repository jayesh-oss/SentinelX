import traceback
import logging

logging.basicConfig(level=logging.INFO)

try:
    from core.scanner import CoreScanner
    from core.behavior_monitor import BehaviorMonitor
    from core.process_monitor import ProcessMonitor
    from PySide6.QtWidgets import QApplication
    from ui.main_window import MainWindow
    import sys
    
    # 1. Scanner
    s = CoreScanner()
    
    # 2. Monitors
    print("Initializing Monitors...")
    monitor = BehaviorMonitor(target_directory="J:\\SentinelX_Test")
    process_monitor = ProcessMonitor(target_directory="J:\\SentinelX_Test")
    
    # 3. GUI
    print("Initializing QApplication...")
    app = QApplication(sys.argv)
    
    print("Initializing MainWindow...")
    window = MainWindow(monitor, process_monitor)
    print("Success! MainWindow Created.")
except Exception as e:
    import traceback
    traceback.print_exc()

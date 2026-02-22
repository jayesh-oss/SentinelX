import sys
from PySide6.QtWidgets import QApplication
import ui.main_window

def trace_init(self):
    print("Trace Start")
    try:
        self.setWindowTitle("SentinelX Antivirus")
        self.setMinimumSize(1000, 650)
        print("L10")
        from PySide6.QtGui import QIcon 
        logo_path = r"C:\Users\pain\.gemini\antigravity\brain\e6eedf20-b819-46dd-9a24-24e211133ff6\sentinelx_logo_1771791546041.png"
        self.setWindowIcon(QIcon(logo_path))
        print("L15")
        from PySide6.QtWidgets import QWidget, QHBoxLayout
        self.central_widget = QWidget()
        print("L18")
        # THIS IS THE PROBLEM?
        super(ui.main_window.MainWindow, self).__init__() # wait I overrode init... Let's just catch all inside __init__
    except Exception as e:
        print("CRASHED", e)

if __name__ == "__main__":
    app = QApplication(sys.argv)
    try:
        w = ui.main_window.MainWindow()
        print("Successfully built MainWindow")
    except Exception as e:
        print("Error:", e)

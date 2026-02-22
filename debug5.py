import sys
from PySide6.QtWidgets import QApplication, QMainWindow, QWidget, QHBoxLayout, QStackedWidget
from ui.tabs.dashboard_tab import DashboardTab
from ui.tabs.scanner_tab import ScannerTab
from ui.tabs.quarantine_tab import QuarantineTab
from ui.tabs.settings_tab import SettingsTab

if __name__ == "__main__":
    app = QApplication(sys.argv)
    print("App created")
    
    class DummyMainWindow(QMainWindow):
        def __init__(self):
            super().__init__()
            print("super ok")
            from PySide6.QtGui import QIcon 
            logo_path = r"C:\Users\pain\.gemini\antigravity\brain\e6eedf20-b819-46dd-9a24-24e211133ff6\sentinelx_logo_1771791546041.png"
            self.setWindowIcon(QIcon(logo_path))
            print("icon ok")
            
            self.central_widget = QWidget()
            self.setCentralWidget(self.central_widget)
            self.main_layout = QHBoxLayout(self.central_widget)
            print("central widget ok")
            
            self.stacked_pages = QStackedWidget()
            print("stacked ok")
            
            print("init dashboard")
            self.page_dashboard = DashboardTab()
            print("done dashboard")
            
            print("init scanner")
            self.page_scanner = ScannerTab()
            print("done scanner")
            
            print("init quarantine")
            self.page_quarantine = QuarantineTab()
            print("done quarantine")
            
            print("init settings")
            self.page_settings = SettingsTab(self)
            print("done settings")
            
            self.stacked_pages.addWidget(self.page_dashboard)
            self.stacked_pages.addWidget(self.page_scanner)
            self.stacked_pages.addWidget(self.page_quarantine)
            self.stacked_pages.addWidget(self.page_settings)
            print("add widget ok")
            
    print("Instantiating Dummy...")
    d = DummyMainWindow()
    print("Dummy Finished!")

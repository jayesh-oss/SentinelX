from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, 
    QPushButton, QLabel, QStackedWidget, QFrame
)
from PySide6.QtCore import Qt, QSize
from PySide6.QtGui import QIcon, QFont, QPixmap
from ui.tabs.scanner_tab import ScannerTab
from ui.tabs.dashboard_tab import DashboardTab
from ui.tabs.quarantine_tab import QuarantineTab
from ui.tabs.settings_tab import SettingsTab

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("SentinelX Antivirus")
        self.setMinimumSize(1000, 650)
        
        # Load the generated logo
        logo_path = r"C:\Users\pain\.gemini\antigravity\brain\e6eedf20-b819-46dd-9a24-24e211133ff6\sentinelx_logo_1771791546041.png"
        self.setWindowIcon(QIcon(logo_path))

        # Central widget
        self.central_widget = QWidget()
        self.setCentralWidget(self.central_widget)
        self.main_layout = QHBoxLayout(self.central_widget)
        self.main_layout.setContentsMargins(0, 0, 0, 0)
        self.main_layout.setSpacing(0)

        # Build UI Components
        self._setup_sidebar()
        self._setup_stacked_pages()

        # Connect signals and ensure data refresh on tab load
        self.btn_dashboard.clicked.connect(self._show_dashboard)
        self.btn_scanner.clicked.connect(lambda: self.stacked_pages.setCurrentIndex(1))
        self.btn_quarantine.clicked.connect(self._show_quarantine)
        self.btn_settings.clicked.connect(lambda: self.stacked_pages.setCurrentIndex(3))

        # Default Page
        self._show_dashboard()

    def _show_dashboard(self):
        self.page_dashboard.refresh_stats()
        self.stacked_pages.setCurrentIndex(0)

    def _show_quarantine(self):
        self.page_quarantine.load_quarantine_data()
        self.stacked_pages.setCurrentIndex(2)

    def _setup_sidebar(self):
        self.sidebar = QFrame()
        self.sidebar.setObjectName("Sidebar")
        self.sidebar.setFixedWidth(220)
        self.sidebar_layout = QVBoxLayout(self.sidebar)
        self.sidebar_layout.setContentsMargins(10, 20, 10, 20)
        self.sidebar_layout.setSpacing(10)

        # Title/Logo
        title_label = QLabel("SentinelX")
        title_label.setObjectName("AppTitle")
        title_label.setAlignment(Qt.AlignCenter)
        self.sidebar_layout.addWidget(title_label)

        self.sidebar_layout.addSpacing(30)

        # Navigation Buttons
        self.btn_dashboard = self._create_nav_button("Dashboard")
        self.btn_scanner = self._create_nav_button("Scanner")
        self.btn_quarantine = self._create_nav_button("Quarantine")
        self.btn_settings = self._create_nav_button("Settings")

        self.sidebar_layout.addWidget(self.btn_dashboard)
        self.sidebar_layout.addWidget(self.btn_scanner)
        self.sidebar_layout.addWidget(self.btn_quarantine)
        self.sidebar_layout.addWidget(self.btn_settings)

        self.sidebar_layout.addStretch() # Push everything up

        # Add to main layout
        self.main_layout.addWidget(self.sidebar)

    def _create_nav_button(self, text):
        btn = QPushButton(text)
        btn.setObjectName("NavButton")
        btn.setCursor(Qt.PointingHandCursor)
        btn.setFixedHeight(45)
        return btn

    def _setup_stacked_pages(self):
        self.stacked_pages = QStackedWidget()
        self.stacked_pages.setObjectName("MainContent")
        
        # Initialize Pages
        self.page_dashboard = DashboardTab() # Use real DashboardTab
        self.page_scanner = ScannerTab() # Use the real ScannerTab
        self.page_quarantine = QuarantineTab() # Use real QuarantineTab
        self.page_settings = SettingsTab(self) # Pass self to control themes

        self.stacked_pages.addWidget(self.page_dashboard)
        self.stacked_pages.addWidget(self.page_scanner)
        self.stacked_pages.addWidget(self.page_quarantine)
        self.stacked_pages.addWidget(self.page_settings)

        self.main_layout.addWidget(self.stacked_pages)

    def apply_custom_theme(self, theme_name):
        styles = {
            "Professional Dark (Default)": """
                QMainWindow { background-color: #0E1117; }
                #Sidebar { background-color: #161B22; border-right: 1px solid #30363D; }
                #AppTitle { color: #58A6FF; font-size: 24px; font-weight: bold; }
                #NavButton { background-color: transparent; color: #C9D1D9; border: none; text-align: left; padding: 15px; font-size: 15px;}
                #NavButton:hover { background-color: #21262D; color: white; }
                #MainContent { background-color: #0D1117; }
            """,
            "Light Mode": """
                QMainWindow { background-color: #F6F8FA; }
                #Sidebar { background-color: #FFFFFF; border-right: 1px solid #D0D7DE; }
                #AppTitle { color: #0969DA; font-size: 24px; font-weight: bold; }
                #NavButton { background-color: transparent; color: #24292F; border: none; text-align: left; padding: 15px; font-size: 15px;}
                #NavButton:hover { background-color: #F3F4F6; }
                #MainContent { background-color: #F6F8FA; }
                QFrame#Card, QFrame#SettingCard, QFrame#StatusFrame, QFrame#StatCard { background-color: #FFFFFF; border: 1px solid #D0D7DE; color: black;}
                QLabel { color: #24292F; }
            """,
            "Hacker Terminal (Green/Black)": """
                QMainWindow { background-color: #000000; }
                #Sidebar { background-color: #050505; border-right: 1px solid #00FF00; }
                #AppTitle { color: #00FF00; font-size: 24px; font-family: Consolas; }
                #NavButton { background-color: black; color: #00FF00; border: 1px solid #00FF00; margin: 2px; text-align: center; font-size: 15px;}
                #NavButton:hover { background-color: #00FF00; color: black; }
                #MainContent { background-color: #000000; }
                QFrame#Card, QFrame#SettingCard, QFrame#StatusFrame, QFrame#StatCard { background-color: #000000; border: 1px solid #00FF00; color: #00FF00;}
                QLabel, QCheckBox { color: #00FF00; font-family: Consolas; }
                QPushButton { background-color: #000000; border: 1px solid #00FF00; color: #00FF00;}
            """,
            "Cyberpunk (Neon Base)": """
                QMainWindow { background-color: #0D0221; }
                #Sidebar { background-color: #12042E; border-right: 2px solid #00F0FF; }
                #AppTitle { color: #FF003C; font-size: 26px; font-weight: bold; text-shadow: 2px 2px #00F0FF;}
                #NavButton { background-color: transparent; color: #00F0FF; border: none; text-align: left; padding: 15px; font-size: 15px;}
                #NavButton:hover { background-color: #FF003C; color: #FFFFFF; }
                #MainContent { background-color: #0D0221; }
                QFrame#Card, QFrame#SettingCard, QFrame#StatusFrame, QFrame#StatCard { background-color: #1A0A3A; border: 1px solid #FF003C; color: white;}
                QLabel, QCheckBox { color: #00F0FF; }
            """,
            "Solarized Dark": """
                QMainWindow { background-color: #002b36; }
                #Sidebar { background-color: #073642; border-right: 1px solid #586e75; }
                #AppTitle { color: #b58900; font-size: 24px; font-weight: bold; }
                #NavButton { background-color: transparent; color: #839496; border: none; text-align: left; padding: 15px; font-size: 15px;}
                #NavButton:hover { background-color: #002b36; color: #93a1a1; }
                #MainContent { background-color: #002b36; }
                QFrame#Card, QFrame#SettingCard, QFrame#StatusFrame, QFrame#StatCard, QFrame#EngineFrame { background-color: #073642; border: 1px solid #586e75; color: #93a1a1;}
                QLabel, QCheckBox { color: #93a1a1; }
            """,
            "SentinelOne EDR (Purple/Dark)": """
                QMainWindow { background-color: #121212; }
                #Sidebar { background-color: #1A1A1A; border-right: 1px solid #4B278D; }
                #AppTitle { color: #9D64FF; font-size: 24px; font-weight: bold; text-transform: uppercase; letter-spacing: 2px; }
                #NavButton { background-color: transparent; color: #E0E0E0; border: none; text-align: left; padding: 15px; font-size: 15px; border-radius: 4px; margin-left: 5px; margin-right: 5px;}
                #NavButton:hover { background-color: #2D1A56; color: white; }
                #NavButton:checked { background-color: #4B278D; color: white; font-weight: bold; }
                #MainContent { background-color: #0A0A0A; }
                QFrame#Card, QFrame#SettingCard, QFrame#StatusFrame, QFrame#StatCard, QFrame#EngineFrame { background-color: #1A1A1A; border: 1px solid #333333; border-top: 3px solid #6E33FF; color: #E0E0E0; border-radius: 6px;}
                QLabel, QCheckBox { color: #E0E0E0; }
                QPushButton { background-color: #4B278D; color: white; border: none; border-radius: 4px; font-weight: bold; }
                QPushButton:hover { background-color: #6E33FF; }
                QProgressBar::chunk { background-color: #9D64FF; }
            """
        }
        
        stylesheet = styles.get(theme_name, styles["Professional Dark (Default)"])
        # We target the specific app instance
        from PySide6.QtWidgets import QApplication
        app = QApplication.instance()
        if app:
            app.setStyleSheet(stylesheet)

    def _add_temp_content(self, widget, text, obj_name):
        layout = QVBoxLayout(widget)
        lbl = QLabel(text)
        lbl.setAlignment(Qt.AlignCenter)
        lbl.setObjectName(obj_name)
        layout.addWidget(lbl)

def load_stylesheet():
    try:
        with open("ui/styles/dark_theme.qss", "r") as f:
            return f.read()
    except FileNotFoundError:
        return ""

if __name__ == "__main__":
    app = QApplication(sys.argv)
    
    # Apply stylesheet
    app.setStyleSheet(load_stylesheet())

    window = MainWindow()
    window.show()
    sys.exit(app.exec())

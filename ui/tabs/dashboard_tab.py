from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame
)
from PySide6.QtCore import Qt, QThread, Signal
from ui.custom_widgets.toggle_button import ToggleSwitch
import sqlite3

class StatCard(QFrame):
    def __init__(self, title, value, color="#58A6FF"):
        super().__init__()
        self.setObjectName("StatCard")
        self.setStyleSheet(f"""
            #StatCard {{
                background-color: #161B22; 
                border-radius: 8px; 
                border: 1px solid #30363D;
                border-top: 4px solid {color};
            }}
        """)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(20, 20, 20, 20)
        
        lbl_title = QLabel(title)
        lbl_title.setStyleSheet("color: #8B949E; font-size: 14px; font-weight: bold;")
        lbl_title.setAlignment(Qt.AlignCenter)
        
        self.lbl_value = QLabel(str(value))
        self.lbl_value.setStyleSheet(f"color: {color}; font-size: 36px; font-weight: bold;")
        self.lbl_value.setAlignment(Qt.AlignCenter)
        
        layout.addWidget(lbl_title)
        layout.addWidget(self.lbl_value)

class DashboardTab(QWidget):
    def __init__(self):
        super().__init__()
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(30, 30, 30, 30)
        self.layout.setSpacing(20)

        # Title
        title = QLabel("System Dashboard")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #E6EDF3;")
        self.layout.addWidget(title)

        # Metrics Layout
        metrics_layout = QHBoxLayout()
        metrics_layout.setSpacing(15)

        self.card_total_scans = StatCard("Total Files Scanned", "0", color="#58A6FF")
        self.card_malware = StatCard("Threats Detected", "0", color="#F85149")
        self.card_quarantine = StatCard("Quarantined Items", "0", color="#D29922")

        metrics_layout.addWidget(self.card_total_scans)
        metrics_layout.addWidget(self.card_malware)
        metrics_layout.addWidget(self.card_quarantine)

        self.layout.addLayout(metrics_layout)

        # Status Area
        status_frame = QFrame()
        status_frame.setObjectName("StatusFrame")
        status_frame.setStyleSheet("""
            #StatusFrame {
                background-color: #161B22; 
                border-radius: 8px; 
                border: 1px solid #30363D;
            }
        """)
        
        status_layout = QVBoxLayout(status_frame)
        
        lbl_status_title = QLabel("Protection Status")
        lbl_status_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #E6EDF3;")
        
        self.lbl_system_status = QLabel("System is Protected")
        self.lbl_system_status.setStyleSheet("color: #3FB950; font-size: 20px; font-weight: bold;")
        
        status_layout.addWidget(lbl_status_title)
        status_layout.addWidget(self.lbl_system_status)
        status_layout.addStretch()

        self.layout.addWidget(status_frame)
        
        # Engine Control Toggles Container
        engine_frame = QFrame()
        engine_frame.setObjectName("EngineFrame")
        engine_frame.setStyleSheet("""
            #EngineFrame {
                background-color: #161B22; 
                border-radius: 8px; 
                border: 1px solid #30363D;
                margin-top: 10px;
            }
        """)
        engine_layout = QVBoxLayout(engine_frame)
        engine_layout.setContentsMargins(20, 20, 20, 20)
        
        lbl_engines = QLabel("Engine Controls")
        lbl_engines.setStyleSheet("font-size: 18px; font-weight: bold; color: #E6EDF3;")
        engine_layout.addWidget(lbl_engines)
        
        self.chk_yara = ToggleSwitch("Enable YARA Memory & File Scanning")
        self.chk_yara.setChecked(True)
        self.chk_yara.setStyleSheet("color: #C9D1D9; font-size: 15px; font-weight: bold; padding: 5px;")
        
        self.chk_behavior = ToggleSwitch("Enable Behavioral & Process Monitoring (Watchdog + WMI)")
        self.chk_behavior.setChecked(True)
        self.chk_behavior.setStyleSheet("color: #C9D1D9; font-size: 15px; font-weight: bold; padding: 5px;")
        
        self.chk_ransomware = ToggleSwitch("Enable Anti-Ransomware Shield [Coming Soon]")
        self.chk_ransomware.setChecked(False)
        self.chk_ransomware.setEnabled(False)
        self.chk_ransomware.setStyleSheet("color: #8B949E; font-size: 15px; padding: 5px;")
        
        engine_layout.addWidget(self.chk_yara)
        engine_layout.addWidget(self.chk_behavior)
        engine_layout.addWidget(self.chk_ransomware)

        # Links area
        link_lbl = QLabel("<a href='https://elastic.github.io/detection-rules-explorer/' style='color: #58A6FF; text-decoration: none;'>View Elastic Detection Rules Explorer</a>")
        link_lbl.setOpenExternalLinks(True)
        link_lbl.setStyleSheet("font-size: 14px; margin-top: 10px;")
        
        engine_layout.addWidget(link_lbl)
        self.layout.addWidget(engine_frame)
        
        self.layout.addStretch()

        self.refresh_stats()

    def refresh_stats(self):
        """Fetches latest stats from SQLite Database."""
        try:
            with sqlite3.connect("database/sentinelx.db") as conn:
                cursor = conn.cursor()
                
                # Total Scans
                cursor.execute("SELECT COUNT(*) FROM scan_history")
                total_scans = cursor.fetchone()[0]
                
                # Malware count
                cursor.execute("SELECT COUNT(*) FROM scan_history WHERE threat_name != 'Clean'")
                malware_scans = cursor.fetchone()[0]

                # Quarantine count
                cursor.execute("SELECT COUNT(*) FROM quarantine_records")
                quarantine_count = cursor.fetchone()[0]

                self.card_total_scans.lbl_value.setText(str(total_scans))
                self.card_malware.lbl_value.setText(str(malware_scans))
                self.card_quarantine.lbl_value.setText(str(quarantine_count))

                if malware_scans > 0:
                    self.lbl_system_status.setText("Threats Detected - Action Required")
                    self.lbl_system_status.setStyleSheet("color: #F85149; font-size: 20px; font-weight: bold;")
                else:
                    self.lbl_system_status.setText("System is Protected")
                    self.lbl_system_status.setStyleSheet("color: #3FB950; font-size: 20px; font-weight: bold;")

        except Exception as e:
            # Handle DB not existing yet gracefully
            print(f"Ignored DB Error on Dashboard Load: {e}")

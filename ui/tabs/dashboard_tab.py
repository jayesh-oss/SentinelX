from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame
)
from PySide6.QtCore import Qt, QThread, Signal, QTimer
from ui.custom_widgets.toggle_button import ToggleSwitch
from ui.custom_widgets.charts import DonutChartWidget
import sqlite3


class StatsWorker(QThread):
    stats_ready = Signal(int, int, int)

    def run(self):
        try:
            with sqlite3.connect("database/sentinelx.db") as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT COUNT(*) FROM scan_history")
                total_scans = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM scan_history WHERE threat_name != 'Clean'")
                malware_scans = cursor.fetchone()[0]
                cursor.execute("SELECT COUNT(*) FROM quarantine_records")
                quarantine_count = cursor.fetchone()[0]
                self.stats_ready.emit(total_scans, malware_scans, quarantine_count)
        except Exception:
            self.stats_ready.emit(0, 0, 0)


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
    def __init__(self, behavior_monitor=None, process_monitor=None):
        super().__init__()
        self.behavior_monitor = behavior_monitor
        self.process_monitor = process_monitor
        self._stats_worker = None

        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(30, 30, 30, 30)
        self.layout.setSpacing(20)

        header_layout = QHBoxLayout()
        title = QLabel("System Dashboard")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #E6EDF3;")
        header_layout.addWidget(title)

        header_layout.addStretch()

        from PySide6.QtWidgets import QPushButton, QMessageBox

        self.btn_reset_stats = QPushButton("Reset Statistics")
        self.btn_reset_stats.setCursor(Qt.PointingHandCursor)
        self.btn_reset_stats.setStyleSheet("padding: 8px 15px; background-color: #21262D; color: #E6EDF3; border-radius: 5px; font-weight: bold; border: 1px solid #30363D;")
        self.btn_reset_stats.clicked.connect(self._reset_statistics)
        header_layout.addWidget(self.btn_reset_stats)

        self.layout.addLayout(header_layout)

        metrics_layout = QHBoxLayout()
        metrics_layout.setSpacing(15)

        self.card_total_scans = StatCard("Total Files Scanned", "0", color="#58A6FF")
        self.card_malware = StatCard("Threats Detected", "0", color="#F85149")
        self.card_quarantine = StatCard("Quarantined Items", "0", color="#D29922")

        metrics_layout.addWidget(self.card_total_scans)
        metrics_layout.addWidget(self.card_malware)
        metrics_layout.addWidget(self.card_quarantine)

        self.layout.addLayout(metrics_layout)

        status_frame = QFrame()
        status_frame.setObjectName("StatusFrame")
        status_frame.setStyleSheet("""
            #StatusFrame {
                background-color: #161B22;
                border-radius: 8px;
                border: 1px solid #30363D;
            }
        """)

        status_layout = QHBoxLayout(status_frame)

        text_lyt = QVBoxLayout()
        lbl_status_title = QLabel("Protection Status")
        lbl_status_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #E6EDF3;")

        self.lbl_system_status = QLabel("System is Protected")
        self.lbl_system_status.setStyleSheet("color: #3FB950; font-size: 20px; font-weight: bold;")

        text_lyt.addWidget(lbl_status_title)
        text_lyt.addWidget(self.lbl_system_status)
        text_lyt.addStretch()

        status_layout.addLayout(text_lyt)
        status_layout.addStretch()

        self.chart = DonutChartWidget(0, 0)
        self.chart.setFixedSize(160, 160)
        status_layout.addWidget(self.chart)

        self.layout.addWidget(status_frame)

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
        b_running = self.behavior_monitor.is_running if self.behavior_monitor else False
        p_running = self.process_monitor.is_running if self.process_monitor else False
        self.chk_behavior.setChecked(b_running or p_running)
        self.chk_behavior.clicked.connect(self.toggle_active_protection)
        self.chk_behavior.setStyleSheet("color: #C9D1D9; font-size: 15px; font-weight: bold; padding: 5px;")

        self.chk_ransomware = ToggleSwitch("Enable Anti-Ransomware Shield")
        self.chk_ransomware.setChecked(True)
        self.chk_ransomware.setEnabled(True)
        self.chk_ransomware.clicked.connect(self.toggle_ransomware_shield)
        self.chk_ransomware.setStyleSheet("color: #C9D1D9; font-size: 15px; font-weight: bold; padding: 5px;")

        # Alert label — hidden until the shield blocks something
        self.lbl_ransomware_alert = QLabel("")
        self.lbl_ransomware_alert.setStyleSheet(
            "color: #F85149; font-weight: bold; font-size: 13px; "
            "background-color: #2D1117; border: 1px solid #F85149; "
            "border-radius: 4px; padding: 6px 10px;"
        )
        self.lbl_ransomware_alert.setWordWrap(True)
        self.lbl_ransomware_alert.setVisible(False)

        engine_layout.addWidget(self.chk_yara)
        engine_layout.addWidget(self.chk_behavior)
        engine_layout.addWidget(self.chk_ransomware)
        engine_layout.addWidget(self.lbl_ransomware_alert)

        # Poll shield for alerts every 2 seconds (non-blocking Qt timer)
        self._shield_timer = QTimer(self)
        self._shield_timer.timeout.connect(self._check_shield_alerts)
        self._shield_timer.start(2000)

        link_lbl = QLabel("<a href='https://elastic.github.io/detection-rules-explorer/' style='color: #58A6FF; text-decoration: none;'>View Elastic Detection Rules Explorer</a>")
        link_lbl.setOpenExternalLinks(True)
        link_lbl.setStyleSheet("font-size: 14px; margin-top: 10px;")

        engine_layout.addWidget(link_lbl)
        self.layout.addWidget(engine_frame)

        self.layout.addStretch()

        self.refresh_stats()

    def _reset_statistics(self):
        from PySide6.QtWidgets import QMessageBox
        reply = QMessageBox.question(
            self, "Confirm Reset",
            "Are you sure you want to reset all dashboard statistics?\nThis will clear your entire scan history. Quarantined files will NOT be deleted.",
            QMessageBox.Yes | QMessageBox.No
        )
        if reply == QMessageBox.Yes:
            try:
                db = sqlite3.connect("database/sentinelx.db")
                cursor = db.cursor()
                cursor.execute("DELETE FROM scan_history")
                cursor.execute("DELETE FROM sqlite_sequence WHERE name='scan_history'")
                db.commit()
                db.close()
                self.refresh_stats()
                QMessageBox.information(self, "Success", "Dashboard statistics have been successfully reset to zero.")
            except Exception as e:
                QMessageBox.critical(self, "Error", f"Failed to reset statistics:\n{e}")

    def refresh_stats(self):
        if self._stats_worker and self._stats_worker.isRunning():
            return
        self._stats_worker = StatsWorker()
        self._stats_worker.stats_ready.connect(self._apply_stats)
        self._stats_worker.start()

    def _apply_stats(self, total_scans, malware_scans, quarantine_count):
        self.card_total_scans.lbl_value.setText(str(total_scans))
        self.card_malware.lbl_value.setText(str(malware_scans))
        self.card_quarantine.lbl_value.setText(str(quarantine_count))

        clean_scans = max(0, total_scans - malware_scans)
        self.chart.update_data(clean_count=clean_scans, malware_count=malware_scans)

        if malware_scans > 0:
            self.lbl_system_status.setText("Threats Detected - Action Required")
            self.lbl_system_status.setStyleSheet("color: #F85149; font-size: 20px; font-weight: bold;")
        else:
            self.lbl_system_status.setText("System is Protected")
            self.lbl_system_status.setStyleSheet("color: #3FB950; font-size: 20px; font-weight: bold;")

    def toggle_ransomware_shield(self):
        from core import engine_registry
        enabled = self.chk_ransomware.isChecked()
        engine_registry.set_ransomware_enabled(enabled)
        shield = engine_registry.get_ransomware_shield()
        if enabled:
            if not shield.is_running:
                shield.start()
        else:
            if shield.is_running:
                shield.stop()
        # Hide the alert banner when the shield is turned off
        if not enabled:
            self.lbl_ransomware_alert.setVisible(False)

    def _check_shield_alerts(self):
        """Called every 2s by QTimer — drains shield alerts and shows them in the banner."""
        try:
            from core import engine_registry
            shield = engine_registry.get_ransomware_shield()
            alerts = shield.pop_alerts()
            if alerts:
                # Show the most recent alert in the banner
                self.lbl_ransomware_alert.setText(f"RANSOMWARE BLOCKED: {alerts[-1]}")
                self.lbl_ransomware_alert.setVisible(True)
                self.refresh_stats()
        except Exception:
            pass

    def toggle_active_protection(self):
        enabled = self.chk_behavior.isChecked()
        if enabled:
            if self.behavior_monitor and not self.behavior_monitor.is_running:
                self.behavior_monitor.start()
            if self.process_monitor and not self.process_monitor.is_running:
                self.process_monitor.start()
        else:
            if self.behavior_monitor and self.behavior_monitor.is_running:
                self.behavior_monitor.stop()
            if self.process_monitor and self.process_monitor.is_running:
                self.process_monitor.stop()

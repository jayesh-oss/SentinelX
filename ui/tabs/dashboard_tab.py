from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QLabel, QFrame, QGraphicsOpacityEffect
)
from PySide6.QtCore import (
    Qt, QThread, Signal, QTimer,
    QPropertyAnimation, QSequentialAnimationGroup, QEasingCurve
)
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

        # ── Opacity effect (created once, reused on every fade_in call) ──
        self._opacity_effect = QGraphicsOpacityEffect(self)
        self.setGraphicsEffect(self._opacity_effect)
        self._fade_anim = QPropertyAnimation(self._opacity_effect, b"opacity")
        self._fade_anim.setDuration(450)
        self._fade_anim.setEasingCurve(QEasingCurve.OutCubic)

        # ── Count-up timer ──
        self._count_timer = QTimer(self)
        self._count_timer.timeout.connect(self._count_step)
        self._target_val = 0
        self._current_val = 0

    # ── Fade in from transparent (called when dashboard tab is shown) ──
    def fade_in(self, delay_ms=0):
        self._fade_anim.stop()
        self._fade_anim.setStartValue(0.0)
        self._fade_anim.setEndValue(1.0)
        if delay_ms > 0:
            QTimer.singleShot(delay_ms, self._fade_anim.start)
        else:
            self._fade_anim.start()

    # ── Count up to value with ease-out ──
    def animate_to(self, value):
        self._target_val = value
        self._current_val = 0
        if value == 0:
            self.lbl_value.setText("0")
            return
        self._count_timer.start(16)

    def _count_step(self):
        remaining = self._target_val - self._current_val
        if remaining <= 0:
            self.lbl_value.setText(str(self._target_val))
            self._count_timer.stop()
            return
        # Ease-out: close fast, slow near the end
        step = max(1, int(remaining * 0.18))
        self._current_val = min(self._current_val + step, self._target_val)
        self.lbl_value.setText(str(self._current_val))


class DashboardTab(QWidget):
    def __init__(self, behavior_monitor=None, process_monitor=None):
        super().__init__()
        self.behavior_monitor = behavior_monitor
        self.process_monitor = process_monitor
        self._stats_worker = None

        # ── Pulse animation refs (prevent GC) ──
        self._pulse_effect = None
        self._pulse_group  = None

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
        self.card_malware     = StatCard("Threats Detected",    "0", color="#F85149")
        self.card_quarantine  = StatCard("Quarantined Items",   "0", color="#D29922")

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

    # ── Called by MainWindow every time the Dashboard tab is shown ──────────
    def animate_in(self):
        self.card_total_scans.fade_in(0)
        self.card_malware.fade_in(90)
        self.card_quarantine.fade_in(180)

    # ── Pulse helpers ────────────────────────────────────────────────────────
    def _start_pulse(self):
        if self._pulse_effect is None:
            self._pulse_effect = QGraphicsOpacityEffect(self.lbl_system_status)
            self.lbl_system_status.setGraphicsEffect(self._pulse_effect)

        if self._pulse_group is not None:
            self._pulse_group.stop()

        fade_out = QPropertyAnimation(self._pulse_effect, b"opacity")
        fade_out.setDuration(800)
        fade_out.setStartValue(1.0)
        fade_out.setEndValue(0.35)
        fade_out.setEasingCurve(QEasingCurve.InOutSine)

        fade_in = QPropertyAnimation(self._pulse_effect, b"opacity")
        fade_in.setDuration(800)
        fade_in.setStartValue(0.35)
        fade_in.setEndValue(1.0)
        fade_in.setEasingCurve(QEasingCurve.InOutSine)

        self._pulse_group = QSequentialAnimationGroup(self)
        self._pulse_group.addAnimation(fade_out)
        self._pulse_group.addAnimation(fade_in)
        self._pulse_group.setLoopCount(-1)
        self._pulse_group.start()

    def _stop_pulse(self):
        if self._pulse_group is not None:
            self._pulse_group.stop()
        if self._pulse_effect is not None:
            self._pulse_effect.setOpacity(1.0)

    # ── Statistics ───────────────────────────────────────────────────────────
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
        # Animated count-up instead of instant setText
        self.card_total_scans.animate_to(total_scans)
        self.card_malware.animate_to(malware_scans)
        self.card_quarantine.animate_to(quarantine_count)

        clean_scans = max(0, total_scans - malware_scans)
        self.chart.update_data(clean_count=clean_scans, malware_count=malware_scans)

        if malware_scans > 0:
            self.lbl_system_status.setText("Threats Detected - Action Required")
            self.lbl_system_status.setStyleSheet("color: #F85149; font-size: 20px; font-weight: bold;")
            self._start_pulse()
        else:
            self.lbl_system_status.setText("System is Protected")
            self.lbl_system_status.setStyleSheet("color: #3FB950; font-size: 20px; font-weight: bold;")
            self._stop_pulse()

    # ── Protection toggles ───────────────────────────────────────────────────
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
        if not enabled:
            self.lbl_ransomware_alert.setVisible(False)

    def _check_shield_alerts(self):
        try:
            from core import engine_registry
            shield = engine_registry.get_ransomware_shield()
            alerts = shield.pop_alerts()
            if alerts:
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

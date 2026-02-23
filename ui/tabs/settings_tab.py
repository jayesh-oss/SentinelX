from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
    QLabel, QComboBox, QCheckBox, QFrame, QMessageBox, QLineEdit, QFileDialog
)
from PySide6.QtCore import Qt
from core.vt_engine import VirusTotalEngine

class SettingsTab(QWidget):
    def __init__(self, main_window, behavior_monitor=None):
        super().__init__()
        self.main_window = main_window # Reference to change themes globally
        self.behavior_monitor = behavior_monitor
        self.vt_engine = VirusTotalEngine()
        
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(30, 30, 30, 30)
        self.layout.setSpacing(20)

        # Title
        title = QLabel("System Settings")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #E6EDF3;")
        self.layout.addWidget(title)
        
        self._build_theme_section()
        self._build_protection_section()
        self._build_api_section()
        
        self.layout.addStretch()

        self.btn_save = QPushButton("Save Settings")
        self.btn_save.setCursor(Qt.PointingHandCursor)
        self.btn_save.setStyleSheet("padding: 10px; background-color: #238636; color: white; border-radius: 5px; font-weight: bold; font-size: 16px;")
        self.btn_save.clicked.connect(self.save_settings)
        self.layout.addWidget(self.btn_save)

    def _build_theme_section(self):
        frame = QFrame()
        frame.setObjectName("SettingCard")
        self._apply_card_style(frame)
        
        lyt = QVBoxLayout(frame)
        lbl = QLabel("Appearance / Themes")
        lbl.setStyleSheet("font-size: 18px; font-weight: bold; color: #E6EDF3;")
        lyt.addWidget(lbl)
        
        h_lyt = QHBoxLayout()
        desc = QLabel("Select the UI Theme:")
        desc.setStyleSheet("color: #8B949E;")
        h_lyt.addWidget(desc)
        
        self.combo_theme = QComboBox()
        self.combo_theme.addItems([
            "Professional Dark (Default)",
            "Light Mode",
            "Hacker Terminal (Green/Black)",
            "Cyberpunk (Neon Base)",
            "Solarized Dark",
            "SentinelOne EDR (Purple/Dark)"
        ])
        self.combo_theme.setStyleSheet("padding: 5px; border-radius: 4px; border: 1px solid #30363D; background-color: #0D1117; color: white;")
        h_lyt.addWidget(self.combo_theme)
        h_lyt.addStretch()
        
        lyt.addLayout(h_lyt)
        
        # Apply theme immediately on change
        self.combo_theme.currentIndexChanged.connect(self.apply_theme)
        
        self.layout.addWidget(frame)

    def _build_protection_section(self):
        frame = QFrame()
        frame.setObjectName("SettingCard")
        self._apply_card_style(frame)
        
        lyt = QVBoxLayout(frame)
        lbl = QLabel("Real-Time Protection")
        lbl.setStyleSheet("font-size: 18px; font-weight: bold; color: #E6EDF3;")
        lyt.addWidget(lbl)
        
        self.chk_realtime = QCheckBox("Enable Watchdog Monitor (Real-Time Protection)")
        self.chk_realtime.setStyleSheet("color: #C9D1D9; font-size: 14px;")
        
        # Read true state
        is_running = self.behavior_monitor.is_running if self.behavior_monitor else False
        self.chk_realtime.setChecked(is_running)
        lyt.addWidget(self.chk_realtime)

        # Configurable Monitor Directory
        h_lyt_dir = QHBoxLayout()
        lbl_dir = QLabel("Monitor Directory:")
        lbl_dir.setStyleSheet("color: #C9D1D9;")
        
        self.txt_monitor_dir = QLineEdit()
        current_dir = self.behavior_monitor.target_directory if self.behavior_monitor else "J:\\SentinelX_Test"
        self.txt_monitor_dir.setText(current_dir)
        self.txt_monitor_dir.setStyleSheet("padding: 5px; border-radius: 4px; border: 1px solid #30363D; background-color: #0D1117; color: white;")
        
        btn_browse_dir = QPushButton("Browse")
        btn_browse_dir.setStyleSheet("padding: 5px; background-color: #21262D; color: white; border-radius: 4px;")
        btn_browse_dir.clicked.connect(self._browse_monitor_dir)

        self.btn_apply_dir = QPushButton("Apply Path")
        self.btn_apply_dir.setStyleSheet("padding: 5px; background-color: #1F6FEB; color: white; border-radius: 4px; font-weight: bold;")
        self.btn_apply_dir.clicked.connect(self._apply_directory)
        
        h_lyt_dir.addWidget(lbl_dir)
        h_lyt_dir.addWidget(self.txt_monitor_dir)
        h_lyt_dir.addWidget(btn_browse_dir)
        h_lyt_dir.addWidget(self.btn_apply_dir)
        lyt.addLayout(h_lyt_dir)

        self.chk_quarantine = QCheckBox("Automatically Quarantine detected payloads")
        self.chk_quarantine.setStyleSheet("color: #C9D1D9; font-size: 14px;")
        
        # Read true state
        auto_quar = self.main_window.page_scanner.auto_quarantine if self.main_window and hasattr(self.main_window, 'page_scanner') else True
        self.chk_quarantine.setChecked(auto_quar)
        lyt.addWidget(self.chk_quarantine)
        
        self.layout.addWidget(frame)

    def _build_api_section(self):
        frame = QFrame()
        frame.setObjectName("SettingCard")
        self._apply_card_style(frame)
        
        lyt = QVBoxLayout(frame)
        lbl = QLabel("Network / API Integrations")
        lbl.setStyleSheet("font-size: 18px; font-weight: bold; color: #E6EDF3;")
        lyt.addWidget(lbl)
        
        lbl_vt = QLabel("VirusTotal API Key:")
        lbl_vt.setStyleSheet("color: #C9D1D9;")
        lyt.addWidget(lbl_vt)
        
        self.txt_vt_key = QLineEdit()
        self.txt_vt_key.setEchoMode(QLineEdit.Password)
        self.txt_vt_key.setPlaceholderText("Enter vt-py API key here...")
        
        # Load existing key if present or default
        if self.vt_engine.api_key:
            self.txt_vt_key.setText(self.vt_engine.api_key)
        else:
            self.txt_vt_key.setText("8d52db4cc162347b8318b52b6574deea12fa8d90f1e0b05714e956ba4f4e8067")
            self.vt_engine.update_key("8d52db4cc162347b8318b52b6574deea12fa8d90f1e0b05714e956ba4f4e8067")
            
        self.txt_vt_key.setStyleSheet("padding: 8px; border-radius: 4px; border: 1px solid #30363D; background-color: #0D1117; color: white;")
        
        # Adding Eye toggle button for API Key visibility
        self.btn_toggle_eye = QPushButton("👁️ Show")
        self.btn_toggle_eye.setStyleSheet("padding: 8px; border-radius: 4px; border: 1px solid #30363D; background-color: #21262D; color: #C9D1D9;")
        self.btn_toggle_eye.clicked.connect(self._toggle_api_visibility)
        
        api_layout = QHBoxLayout()
        api_layout.addWidget(self.txt_vt_key)
        api_layout.addWidget(self.btn_toggle_eye)
        
        lyt.addLayout(api_layout)
        
        self.layout.addWidget(frame)

    def _toggle_api_visibility(self):
        if self.txt_vt_key.echoMode() == QLineEdit.Password:
            self.txt_vt_key.setEchoMode(QLineEdit.Normal)
            self.btn_toggle_eye.setText("🙈 Hide")
        else:
            self.txt_vt_key.setEchoMode(QLineEdit.Password)
            self.btn_toggle_eye.setText("👁️ Show")

    def _browse_monitor_dir(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Select Monitor Directory")
        if folder_path:
            import os
            self.txt_monitor_dir.setText(os.path.normpath(folder_path))
            self._apply_directory()

    def _apply_directory(self):
        new_dir = self.txt_monitor_dir.text().strip()
        if not new_dir:
            return
            
        import time
        if self.behavior_monitor:
            was_running = self.behavior_monitor.is_running
            if was_running:
                self.behavior_monitor.stop()
                time.sleep(0.5)
            self.behavior_monitor.target_directory = new_dir
            if was_running:
                self.behavior_monitor.start()
                
        if self.main_window and hasattr(self.main_window, 'process_monitor') and self.main_window.process_monitor:
            was_p_running = self.main_window.process_monitor.is_running
            if was_p_running:
                self.main_window.process_monitor.stop()
                time.sleep(0.5)
            self.main_window.process_monitor.target_directory = new_dir
            if was_p_running:
                self.main_window.process_monitor.start()

        import logging
        logging.info(f"Monitor Directory dynamically updated to: {new_dir}")
        QMessageBox.information(self, "Directory Applied", f"Monitor directory successfully updated to:\n{new_dir}")

    def _apply_card_style(self, frame):
        frame.setStyleSheet("""
            #SettingCard {
                background-color: #161B22; 
                border-radius: 8px; 
                border: 1px solid #30363D;
                padding: 10px;
            }
        """)

    def apply_theme(self):
        theme_name = self.combo_theme.currentText()
        if self.main_window:
            self.main_window.apply_custom_theme(theme_name)

    def save_settings(self):
        # Save VT Engine key
        new_key = self.txt_vt_key.text().strip()
        self.vt_engine.update_key(new_key)
        
        # Apply Protection Settings
        new_dir = self.txt_monitor_dir.text().strip()
        
        import time
        if self.behavior_monitor:
            was_running = self.behavior_monitor.is_running
            if was_running:
                self.behavior_monitor.stop()
                time.sleep(0.5) # Allow thread to die
            self.behavior_monitor.target_directory = new_dir
            if self.chk_realtime.isChecked():
                self.behavior_monitor.start()
                
        # Also update process monitor directory
        if self.main_window and hasattr(self.main_window, 'process_monitor') and self.main_window.process_monitor:
            was_p_running = self.main_window.process_monitor.is_running
            if was_p_running:
                self.main_window.process_monitor.stop()
                time.sleep(0.5) # Allow thread to die
            self.main_window.process_monitor.target_directory = new_dir
            if self.chk_realtime.isChecked():
                self.main_window.process_monitor.start()

        if self.main_window and hasattr(self.main_window, 'page_scanner'):
            self.main_window.page_scanner.auto_quarantine = self.chk_quarantine.isChecked()
        
        QMessageBox.information(self, "Settings Saved", "Preferences and Protection configurations have been saved successfully.")

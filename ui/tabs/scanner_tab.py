import os
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
    QLabel, QFileDialog, QProgressBar, QTextEdit, QFrame
)
from PySide6.QtCore import Qt, QThread, Signal
import yara
from core.scanner import CoreScanner
from core.yara_engine import YaraEngine
from database.db_manager import DatabaseManager
from core.vt_engine import VirusTotalEngine
from core.quarantine import QuarantineManager

class ScanThread(QThread):
    progress = Signal(int)
    max_progress = Signal(int)
    result = Signal(dict)
    finished = Signal()

    def __init__(self, target_paths):
        super().__init__()
        # target_paths is a list of file paths
        self.target_paths = target_paths
        self.scanner = CoreScanner()
        self.yara_engine = YaraEngine()
        self.vt_engine = VirusTotalEngine()

    def run(self):
        total_files = len(self.target_paths)
        if total_files == 0:
            self.finished.emit()
            return
            
        self.max_progress.emit(total_files)

        for i, path in enumerate(self.target_paths):
            try:
                # Basic progress
                res = self.scanner.scan_file(path)

                # Yara scanning
                yara_matches = self.yara_engine.scan_file(path)
                res['yara_matches'] = yara_matches
                
                # VirusTotal Integration
                file_hash = res.get('hashes', {}).get('md5', '')
                if file_hash:
                    vt_result = self.vt_engine.lookup_hash(file_hash)
                    res['vt_result'] = vt_result

                # Determine overall Threat
                if yara_matches:
                    res['threat_level'] = f"Malicious ({', '.join(yara_matches)})"
                elif res.get('vt_result', {}).get('status') in ['success', 'cached']:
                    vt_data = res.get('vt_result', {}).get('data', {})
                    if vt_data and vt_data.get('malicious', 0) >= 3:
                        res['threat_level'] = f"Malicious (Cloud: {vt_data['malicious']}/{vt_data['total']})"
                    
                self.result.emit(res)
            except Exception as e:
                print(f"Error scanning {path}: {e}")
                
            self.progress.emit(i + 1)
            
        self.finished.emit()

class ScannerTab(QWidget):
    def __init__(self):
        super().__init__()
        self.quarantine_mgr = QuarantineManager()
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(30, 30, 30, 30)
        self.layout.setSpacing(20)

        # Title
        title = QLabel("System Scanner")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #E6EDF3;")
        self.layout.addWidget(title)

        # Controls Container
        controls_frame = QFrame()
        controls_frame.setObjectName("Card")
        controls_frame.setStyleSheet("""
            #Card {
                background-color: #161B22; 
                border-radius: 8px; 
                border: 1px solid #30363D;
            }
        """)
        
        controls_layout = QVBoxLayout(controls_frame)
        controls_layout.setContentsMargins(20, 20, 20, 20)
        controls_layout.setSpacing(15)
        
        # File path label
        self.lbl_file_path = QLabel("No targets selected...")
        self.lbl_file_path.setStyleSheet("color: #8B949E; font-size: 14px;")
        controls_layout.addWidget(self.lbl_file_path)

        # Buttons
        btn_layout = QHBoxLayout()
        self.btn_browse = QPushButton("Browse File")
        self.btn_browse.setCursor(Qt.PointingHandCursor)
        self.btn_browse.setStyleSheet("padding: 10px; background-color: #21262D; color: white; border-radius: 5px;")
        
        self.btn_browse_folder = QPushButton("Browse Folder")
        self.btn_browse_folder.setCursor(Qt.PointingHandCursor)
        self.btn_browse_folder.setStyleSheet("padding: 10px; background-color: #21262D; color: white; border-radius: 5px;")

        self.btn_scan = QPushButton("Start Scan")
        self.btn_scan.setCursor(Qt.PointingHandCursor)
        self.btn_scan.setStyleSheet("padding: 10px; background-color: #1F6FEB; color: white; border-radius: 5px; font-weight: bold;")
        self.btn_scan.setEnabled(False)

        btn_layout.addWidget(self.btn_browse)
        btn_layout.addWidget(self.btn_browse_folder)
        btn_layout.addWidget(self.btn_scan)
        btn_layout.addStretch()
        
        controls_layout.addLayout(btn_layout)
        
        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(False)
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #30363D;
                border-radius: 4px;
                background-color: #0D1117;
                height: 8px;
            }
            QProgressBar::chunk {
                background-color: #238636;
                border-radius: 4px;
            }
        """)
        controls_layout.addWidget(self.progress_bar)

        self.layout.addWidget(controls_frame)

        # Results Area
        results_title = QLabel("Scan Results")
        results_title.setStyleSheet("font-size: 18px; font-weight: bold; color: #E6EDF3;")
        self.layout.addWidget(results_title)

        self.txt_results = QTextEdit()
        self.txt_results.setReadOnly(True)
        self.txt_results.setStyleSheet("""
            QTextEdit {
                background-color: #0D1117;
                border: 1px solid #30363D;
                border-radius: 8px;
                color: #C9D1D9;
                font-family: Consolas, monospace;
                padding: 15px;
            }
        """)
        self.layout.addWidget(self.txt_results)

        # Connect signals
        self.btn_browse.clicked.connect(self.browse_file)
        self.btn_browse_folder.clicked.connect(self.browse_folder)
        self.btn_scan.clicked.connect(self.start_scan)
        
        self.target_files = []
        self.scan_thread = None

    def browse_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select File to Scan", "", "All Files (*.*)")
        if file_path:
            self.target_files = [os.path.normpath(file_path)]
            self.lbl_file_path.setText(f"Selected: {self.target_files[0]}")
            self.btn_scan.setEnabled(True)
            self.txt_results.clear()

    def browse_folder(self):
        folder_path = QFileDialog.getExistingDirectory(self, "Select Folder to Scan")
        if folder_path:
            self.target_files = []
            for root, _, files in os.walk(folder_path):
                for file in files:
                    self.target_files.append(os.path.normpath(os.path.join(root, file)))
            
            self.lbl_file_path.setText(f"Selected Folder: {folder_path} ({len(self.target_files)} files)")
            self.btn_scan.setEnabled(len(self.target_files) > 0)
            self.txt_results.clear()

    def start_scan(self):
        if not self.target_files:
            return
            
        self.btn_scan.setEnabled(False)
        self.btn_browse.setEnabled(False)
        self.btn_browse_folder.setEnabled(False)
        self.txt_results.clear()
        self.progress_bar.setValue(0)
        
        self.scan_thread = ScanThread(self.target_files)
        self.scan_thread.max_progress.connect(self.progress_bar.setMaximum)
        self.scan_thread.progress.connect(self.progress_bar.setValue)
        self.scan_thread.result.connect(self.display_results)
        self.scan_thread.finished.connect(self.scan_finished)
        self.scan_thread.start()
        
    def display_results(self, result):
        threat_level = result.get('threat_level', 'Unknown')
        
        if threat_level != "Clean":
            color = "#F85149" # Red
        else:
            color = "#3FB950" # Green

        html = f"""
        <h2 style='color: {color}; margin-top: 0;'>Status: {threat_level}</h2>
        <hr style='background-color: #30363D; border: none; height: 1px;'/>
        <p><b>Target:</b> {result['file']}</p>
        """
        
        hashes = result.get('hashes', {})
        html += f"<p><b>MD5:</b> {hashes.get('md5')}<br/>"
        html += f"<b>SHA1:</b> {hashes.get('sha1')}<br/>"
        html += f"<b>SHA256:</b> {hashes.get('sha256')}</p>"

        pe = result.get('pe_analysis', {})
        if pe.get('is_pe'):
            html += f"<p><b>PE Executable:</b> Yes<br/>"
            html += f"<b>Entropy:</b> {pe.get('entropy', 0):.2f}<br/>"
            html += f"<b>Sections:</b> {pe.get('number_of_sections', 0)}</p>"
            
            suspicious = pe.get('suspicious_imports', [])
            if suspicious:
                html += f"<p style='color: #F85149;'><b>Suspicious API Calls Detected:</b><br/>"
                html += "<br/>".join(suspicious) + "</p>"

        yara = result.get('yara_matches', [])
        if yara:
            html += f"<p style='color: #F85149;'><b>YARA Rule Matches:</b><br/>"
            html += "<br/>".join([match for match in yara]) + "</p>"

        vt = result.get('vt_result', {})
        html += "<p><b>VirusTotal Analysis:</b> "
        if vt.get('status') == 'error':
             html += "<span style='color: #D29922;'>API Error / No Key Configured</span></p>"
        elif vt.get('status') == 'not_found':
             html += "Hash not found in VT database.</p>"
        elif vt.get('status') in ['success', 'cached'] and vt.get('data'):
             vt_data = vt['data']
             score_color = "#3FB950" if vt_data['malicious'] == 0 else "#F85149"
             html += f"<span style='color: {score_color}; font-weight: bold;'>{vt_data['malicious']} / {vt_data['total']}</span> detections.<br/>"
             html += f"<a href='{vt_data['permalink']}' style='color: #58A6FF;'>View Full Report</a></p>"

        # ML Score
        html += f"<p><b>ML Score:</b> {result.get('ml_score', 0.0)}</p>"
        
        # Determine Auto Quarantine
        if threat_level != "Clean":
            file_path = result['file']
            file_hash = hashes.get('md5', 'unknown')
            success = self.quarantine_mgr.quarantine_file(file_path, threat_level, file_hash)
            if success:
                 html += f"<p style='color: #D29922; font-weight: bold;'>⚠️ ACTION TAKEN: File has been automatically Quarantined.</p>"
            else:
                 html += f"<p style='color: #F85149; font-weight: bold;'>🚨 ACTION FAILED: Could not quarantine file.</p>"

        # Prepend to results so newest is at the top
        current_html = self.txt_results.toHtml()
        self.txt_results.setHtml(html + current_html)

        # Log to Database
        try:
            db = DatabaseManager()
            db.log_scan(
                file_path=result['file'],
                scan_type="Manual UI Scan",
                result="Malicious" if threat_level != "Clean" else "Clean",
                threat_name=threat_level if threat_level != "Clean" else "None"
            )
        except Exception as e:
            print(f"Error logging scan to DB: {e}")

    def scan_finished(self):
        self.btn_scan.setEnabled(True)
        self.btn_browse.setEnabled(True)
        self.btn_browse_folder.setEnabled(True)
        # Prevent bar from staying empty if max was 0
        self.progress_bar.setValue(self.progress_bar.maximum())

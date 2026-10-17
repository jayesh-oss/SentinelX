import os
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton,
    QLabel, QFileDialog, QProgressBar, QTextEdit, QFrame
)
from PySide6.QtCore import Qt, QThread, Signal
from core import engine_registry


class ScanThread(QThread):
    progress = Signal(int)
    max_progress = Signal(int)
    status = Signal(str)
    result = Signal(dict)
    finished = Signal()

    def __init__(self, target_paths):
        super().__init__()
        self.target_paths = target_paths
        self.scanner = engine_registry.get_scanner()
        self.yara_engine = engine_registry.get_yara_engine()
        self.vt_engine = engine_registry.get_vt_engine()
        self.ransomware_engine = engine_registry.get_ransomware_engine()

    def run(self):
        total_files = len(self.target_paths)
        if total_files == 0:
            self.finished.emit()
            return

        self.max_progress.emit(total_files)

        for i, path in enumerate(self.target_paths):
            file_name = os.path.basename(path)
            try:
                self.status.emit(f"[{i+1}/{total_files}] Reading & hashing: {file_name}")
                res = self.scanner.scan_file(path)

                self.status.emit(f"[{i+1}/{total_files}] YARA scanning ({self.yara_engine.rule_count} rules): {file_name}")
                yara_matches = list(dict.fromkeys(self.yara_engine.scan_file(path)))
                res['yara_matches'] = yara_matches

                file_hash = res.get('hashes', {}).get('md5', '')
                if file_hash:
                    self.status.emit(f"[{i+1}/{total_files}] VirusTotal lookup: {file_name}")
                    vt_result = self.vt_engine.lookup_hash(file_hash)
                    res['vt_result'] = vt_result

                self.status.emit(f"[{i+1}/{total_files}] Visual CNN analysis: {file_name}")
                # visual_cnn result is already in res from scan_file()

                self.status.emit(f"[{i+1}/{total_files}] Evaluating threat score: {file_name}")
                vt_data = res.get('vt_result', {}).get('data') if res.get('vt_result', {}).get('status') in ['success', 'cached'] else None
                res = self.scanner.evaluate_threat(res, yara_matches, vt_data)

                res['yara_matches'] = yara_matches

                # ── Ransomware detection (runs only when shield is enabled) ──
                if engine_registry.is_ransomware_enabled():
                    self.status.emit(f"[{i+1}/{total_files}] Ransomware analysis: {file_name}")
                    rw_result = self.ransomware_engine.analyze(
                        file_path=path,
                        pe_analysis=res.get('pe_analysis', {}),
                    )
                    res['ransomware_analysis'] = rw_result

                self.result.emit(res)
            except Exception as e:
                self.status.emit(f"[{i+1}/{total_files}] ERROR: {file_name} — {e}")

            self.progress.emit(i + 1)

        self.status.emit(f"Scan complete — {total_files} file(s) processed.")
        self.finished.emit()


class ScannerTab(QWidget):
    def __init__(self):
        super().__init__()
        self.quarantine_mgr = engine_registry.get_quarantine_manager()
        self.auto_quarantine = True
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
        
        self.lbl_status = QLabel("Ready.")
        self.lbl_status.setStyleSheet("color: #58A6FF; font-size: 13px; font-family: Consolas, monospace;")
        controls_layout.addWidget(self.lbl_status)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        self.progress_bar.setTextVisible(True)
        self.progress_bar.setFormat("%v / %m files")
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 1px solid #30363D;
                border-radius: 4px;
                background-color: #0D1117;
                height: 20px;
                color: #8B949E;
                font-size: 12px;
                text-align: center;
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

        from PySide6.QtWidgets import QTextBrowser
        self.txt_results = QTextBrowser()
        self.txt_results.setOpenExternalLinks(True)
        self.txt_results.setStyleSheet("""
            QTextBrowser {
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
        self.lbl_status.setText("Initializing scan...")
        self.lbl_status.setStyleSheet("color: #D29922; font-size: 13px; font-family: Consolas, monospace;")

        self.scan_thread = ScanThread(self.target_files)
        self.scan_thread.max_progress.connect(self.progress_bar.setMaximum)
        self.scan_thread.progress.connect(self.progress_bar.setValue)
        self.scan_thread.status.connect(self._update_status)
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
            html += f"<b>Overall Entropy:</b> {pe.get('entropy', 0):.2f}<br/>"
            html += f"<b>Sections:</b> {pe.get('number_of_sections', 0)}</p>"

            # Section entropy table
            sections = pe.get('section_analysis', [])
            if sections:
                html += "<table style='border-collapse:collapse; width:100%; margin:8px 0;'>"
                html += "<tr style='background:#161B22;'>"
                html += "<th style='padding:4px 8px; border:1px solid #30363D; color:#58A6FF;'>Section</th>"
                html += "<th style='padding:4px 8px; border:1px solid #30363D; color:#58A6FF;'>Entropy</th>"
                html += "<th style='padding:4px 8px; border:1px solid #30363D; color:#58A6FF;'>Raw Size</th>"
                html += "<th style='padding:4px 8px; border:1px solid #30363D; color:#58A6FF;'>Virtual Size</th></tr>"
                for sec in sections:
                    ent = sec.get('entropy', 0)
                    ent_color = '#F85149' if ent > 7.2 else ('#D29922' if ent > 6.5 else '#3FB950')
                    html += f"<tr><td style='padding:4px 8px; border:1px solid #30363D;'>{sec['name']}</td>"
                    html += f"<td style='padding:4px 8px; border:1px solid #30363D; color:{ent_color};'>{ent:.2f}</td>"
                    html += f"<td style='padding:4px 8px; border:1px solid #30363D;'>{sec.get('raw_size', 0):,}</td>"
                    html += f"<td style='padding:4px 8px; border:1px solid #30363D;'>{sec.get('virtual_size', 0):,}</td></tr>"
                html += "</table>"

            # Threat category tags
            threat_cats = pe.get('threat_categories', {})
            if threat_cats:
                cat_colors = {
                    "Process Injection": "#F85149", "Crypto (Ransomware)": "#F85149",
                    "Credential Access": "#F85149", "Evasion / Anti-Debug": "#D29922",
                    "Networking": "#D29922", "Persistence": "#D29922",
                    "Code Loading": "#58A6FF", "Memory Manipulation": "#58A6FF",
                    "Process / Thread Control": "#8B949E",
                }
                html += "<p><b>Threat Categories:</b><br/>"
                for cat, apis in threat_cats.items():
                    c = cat_colors.get(cat, '#C9D1D9')
                    html += f"<span style='display:inline-block; background:{c}22; color:{c}; border:1px solid {c}; border-radius:4px; padding:2px 8px; margin:2px 4px 2px 0; font-size:12px;'>{cat} ({len(apis)})</span>"
                html += "</p>"

            # Full suspicious imports list
            suspicious = pe.get('suspicious_imports', [])
            if suspicious:
                html += f"<p style='color: #F85149;'><b>Suspicious API Calls ({len(suspicious)}):</b><br/>"
                html += "<br/>".join(suspicious) + "</p>"

            # IAT summary by DLL
            imports = pe.get('imports', {})
            if imports:
                html += f"<details><summary style='color:#58A6FF; cursor:pointer;'><b>Import Address Table ({len(imports)} DLLs)</b></summary>"
                html += "<table style='border-collapse:collapse; width:100%; margin:8px 0;'>"
                html += "<tr style='background:#161B22;'>"
                html += "<th style='padding:4px 8px; border:1px solid #30363D; color:#58A6FF;'>DLL</th>"
                html += "<th style='padding:4px 8px; border:1px solid #30363D; color:#58A6FF;'>Functions</th></tr>"
                for dll, funcs in imports.items():
                    func_names = ", ".join(f['name'] for f in funcs[:20])
                    if len(funcs) > 20:
                        func_names += f" ... (+{len(funcs)-20} more)"
                    html += f"<tr><td style='padding:4px 8px; border:1px solid #30363D; color:#D29922;'>{dll}</td>"
                    html += f"<td style='padding:4px 8px; border:1px solid #30363D; font-size:12px;'>{func_names}</td></tr>"
                html += "</table></details>"

            # Anomalies
            anomalies = pe.get('anomalies', [])
            if anomalies:
                html += f"<p style='color: #F85149;'><b>PE Anomalies ({len(anomalies)}):</b><br/>"
                for a in anomalies:
                    html += f"&bull; {a}<br/>"
                html += "</p>"

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

        # ML Score (RandomForest)
        html += f"<p><b>ML Heuristic Score:</b> {result.get('ml_score', 0.0)}</p>"

        # Visual CNN Results
        visual = result.get('visual_cnn', {})
        if visual.get('available'):
            v_score = visual.get('score', 0.0)
            v_family = visual.get('family', 'Unknown')
            v_conf = visual.get('confidence', 0.0)
            v_color = '#F85149' if v_score >= 0.7 else ('#D29922' if v_score >= 0.5 else '#3FB950')

            html += f"""
            <div style='background:#161B22; border:1px solid #30363D; border-radius:8px; padding:12px; margin:8px 0;'>
                <p style='color:#A371F7; font-weight:bold; font-size:14px; margin:0 0 8px 0;'>Visual CNN Analysis (EfficientNet-B0)</p>
                <p style='margin:4px 0;'><b>Malware Score:</b> <span style='color:{v_color}; font-weight:bold;'>{v_score:.2f}</span></p>
                <p style='margin:4px 0;'><b>Predicted Family:</b> <span style='color:#A371F7; font-weight:bold;'>{v_family}</span> ({v_conf:.1%} confidence)</p>
            """
            top3 = visual.get('top3', [])
            if top3:
                html += "<p style='margin:4px 0;'><b>Top Predictions:</b></p>"
                html += "<table style='border-collapse:collapse; width:100%; margin:4px 0;'>"
                html += "<tr style='background:#0D1117;'>"
                html += "<th style='padding:3px 8px; border:1px solid #30363D; color:#A371F7; font-size:12px;'>Family</th>"
                html += "<th style='padding:3px 8px; border:1px solid #30363D; color:#A371F7; font-size:12px;'>Confidence</th></tr>"
                for pred in top3:
                    p_color = '#F85149' if pred['name'] != 'Benign' else '#3FB950'
                    html += f"<tr><td style='padding:3px 8px; border:1px solid #30363D; color:{p_color};'>{pred['name']}</td>"
                    html += f"<td style='padding:3px 8px; border:1px solid #30363D;'>{pred['confidence']:.1%}</td></tr>"
                html += "</table>"
            html += "</div>"

            # Display grayscale visualization of the binary
            grayscale_bytes = visual.get('grayscale_png')
            if grayscale_bytes:
                import base64
                b64 = base64.b64encode(grayscale_bytes).decode('ascii')
                html += f"""
                <details><summary style='color:#A371F7; cursor:pointer;'><b>Binary Visualization (Grayscale 256x256)</b></summary>
                <div style='text-align:center; padding:8px;'>
                    <img src='data:image/png;base64,{b64}' width='256' height='256'
                         style='border:1px solid #30363D; image-rendering:pixelated;'/>
                    <p style='color:#8B949E; font-size:11px;'>Each pixel = one byte of the binary (0x00=black, 0xFF=white)</p>
                </div>
                </details>
                """
        else:
            html += "<p style='color:#8B949E;'><b>Visual CNN:</b> Model not loaded — run training script first (tools/train_visual_model.py)</p>"
        
        # ── Anti-Ransomware Detection Results ────────────────────────────────
        rw = result.get('ransomware_analysis')
        if rw:
            rw_verdict = rw.get('verdict', 'Clean')
            rw_score = rw.get('score', 0)
            if rw_verdict == 'Ransomware':
                rw_color = '#F85149'
                rw_border = '#F85149'
            elif 'Suspicious' in rw_verdict:
                rw_color = '#D29922'
                rw_border = '#D29922'
            else:
                rw_color = '#3FB950'
                rw_border = '#238636'

            html += f"""
            <div style='background:#0D0A1A; border:2px solid {rw_border}; border-radius:8px; padding:14px; margin:10px 0;'>
                <p style='color:#A371F7; font-weight:bold; font-size:15px; margin:0 0 10px 0;'>
                    Anti-Ransomware Detection Report
                </p>
                <p style='margin:4px 0;'>
                    <b>Verdict:</b>
                    <span style='color:{rw_color}; font-weight:bold; font-size:14px;'>&nbsp;{rw_verdict}</span>
                    &nbsp;&nbsp;<span style='color:#8B949E; font-size:12px;'>Risk Score: {rw_score}</span>
                </p>
            """

            ext_v = rw.get('extension_verdict', 'Clean')
            ext_color = '#F85149' if ext_v != 'Clean' else '#3FB950'
            html += f"<p style='margin:4px 0;'><b>Extension Check:</b> <span style='color:{ext_color};'>{ext_v}</span></p>"

            ent_v = rw.get('entropy_verdict', 'N/A')
            if ent_v != 'N/A':
                ent_color = '#F85149' if 'High' in ent_v else ('#D29922' if 'Elevated' in ent_v else '#3FB950')
                html += f"<p style='margin:4px 0;'><b>Entropy Analysis:</b> <span style='color:{ent_color};'>{ent_v}</span></p>"

            crypto = rw.get('crypto_apis', [])
            if crypto:
                html += f"<p style='margin:4px 0;'><b>Ransomware Crypto APIs:</b> <span style='color:#F85149;'>{', '.join(crypto[:5])}</span></p>"

            ransom_strs = rw.get('ransom_strings_found', [])
            if ransom_strs:
                html += f"<p style='margin:4px 0;'><b>Ransom Strings in Binary:</b> <span style='color:#F85149;'>{', '.join(ransom_strs[:3])}</span></p>"

            if rw.get('anti_recovery'):
                html += "<p style='margin:4px 0;'><b>Anti-Recovery:</b> <span style='color:#F85149;'>Shadow copy / VSS deletion capability detected</span></p>"

            indicators = rw.get('indicators', [])
            if indicators:
                html += "<p style='margin:6px 0 2px 0;'><b>Indicators:</b></p><ul style='margin:2px 0; padding-left:20px;'>"
                for ind in indicators:
                    html += f"<li style='color:#C9D1D9; font-size:13px;'>{ind}</li>"
                html += "</ul>"

            if 'error' in rw:
                html += f"<p style='color:#8B949E; font-size:12px;'>Analysis error: {rw['error']}</p>"

            html += "</div>"

        # Determine Auto Quarantine
        if threat_level != "Clean":
            if self.auto_quarantine:
                file_path = result['file']
                file_hash = hashes.get('md5', 'unknown')
                success = self.quarantine_mgr.quarantine_file(file_path, threat_level, file_hash)
                if success:
                     html += f"<p style='color: #D29922; font-weight: bold;'>⚠️ ACTION TAKEN: File has been automatically Quarantined.</p>"
                else:
                     html += f"<p style='color: #F85149; font-weight: bold;'>🚨 ACTION FAILED: Could not quarantine file.</p>"
            else:
                html += f"<p style='color: #D29922; font-weight: bold;'>⚠️ AUTO-QUARANTINE DISABLED. Manual verification required.</p>"

        # Insert at top so newest result appears first — O(1), no full-doc rebuild
        from PySide6.QtGui import QTextCursor
        cursor = self.txt_results.textCursor()
        cursor.movePosition(QTextCursor.MoveOperation.Start)
        self.txt_results.setTextCursor(cursor)
        self.txt_results.insertHtml(html + "<hr style='background-color:#30363D; border:none; height:1px; margin:12px 0;'/>")

        # Log to Database
        try:
            db = engine_registry.get_db()
            db.log_scan(
                file_path=result['file'],
                scan_type="Manual UI Scan",
                result="Malicious" if threat_level != "Clean" else "Clean",
                threat_name=threat_level if threat_level != "Clean" else "None"
            )
        except Exception as e:
            print(f"Error logging scan to DB: {e}")

    def _update_status(self, text):
        self.lbl_status.setText(text)

    def scan_finished(self):
        self.btn_scan.setEnabled(True)
        self.btn_browse.setEnabled(True)
        self.btn_browse_folder.setEnabled(True)
        self.progress_bar.setValue(self.progress_bar.maximum())
        self.lbl_status.setStyleSheet("color: #3FB950; font-size: 13px; font-family: Consolas, monospace;")

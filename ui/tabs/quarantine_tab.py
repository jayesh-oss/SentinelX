import os
import sqlite3
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QPushButton, 
    QLabel, QTableWidget, QTableWidgetItem, QHeaderView, QMessageBox, QCheckBox
)
from PySide6.QtCore import Qt
from core.quarantine import QuarantineManager

class QuarantineTab(QWidget):
    def __init__(self):
        super().__init__()
        self.quarantine_manager = QuarantineManager()
        
        self.layout = QVBoxLayout(self)
        self.layout.setContentsMargins(30, 30, 30, 30)
        self.layout.setSpacing(20)

        # Title
        title = QLabel("Quarantine Manager")
        title.setStyleSheet("font-size: 24px; font-weight: bold; color: #E6EDF3;")
        self.layout.addWidget(title)

        # Description
        desc = QLabel("Isolated files are stored safely here and cannot execute. You can restore safe files or permanently delete threats.")
        desc.setStyleSheet("color: #8B949E; font-size: 14px;")
        desc.setWordWrap(True)
        self.layout.addWidget(desc)

        # Table
        self.table = QTableWidget()
        self.table.setColumnCount(6)
        self.table.setHorizontalHeaderLabels(["Select", "ID", "Original Path", "Threat Name", "Hash", "Date Quarantined"])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeToContents)
        self.table.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeToContents)
        
        self.table.setStyleSheet("""
            QTableWidget {
                background-color: #0D1117;
                border: 1px solid #30363D;
                border-radius: 8px;
                color: #C9D1D9;
                gridline-color: #30363D;
            }
            QHeaderView::section {
                background-color: #161B22;
                color: #8B949E;
                font-weight: bold;
                border: none;
                border-right: 1px solid #30363D;
                border-bottom: 1px solid #30363D;
                padding: 5px;
            }
        """)
        self.layout.addWidget(self.table)

        # Action Buttons
        btn_layout = QHBoxLayout()
        
        self.btn_refresh = QPushButton("Refresh List")
        self.btn_refresh.setCursor(Qt.PointingHandCursor)
        self.btn_refresh.setStyleSheet("padding: 10px; background-color: #21262D; color: white; border-radius: 5px;")
        
        self.chk_select_all = QCheckBox("Select All")
        self.chk_select_all.setStyleSheet("color: #E6EDF3; font-weight: bold; margin-left: 20px;")
        self.chk_select_all.toggled.connect(self.toggle_select_all)
        
        self.btn_restore = QPushButton("Restore Selected")
        self.btn_restore.setCursor(Qt.PointingHandCursor)
        self.btn_restore.setStyleSheet("padding: 10px; background-color: #D29922; color: black; border-radius: 5px; font-weight: bold;")
        
        self.btn_delete = QPushButton("Delete Selected")
        self.btn_delete.setCursor(Qt.PointingHandCursor)
        self.btn_delete.setStyleSheet("padding: 10px; background-color: #F85149; color: white; border-radius: 5px; font-weight: bold;")

        btn_layout.addWidget(self.btn_refresh)
        btn_layout.addWidget(self.chk_select_all)
        btn_layout.addStretch()
        btn_layout.addWidget(self.btn_restore)
        btn_layout.addWidget(self.btn_delete)
        
        self.layout.addLayout(btn_layout)

        # Connect Signals
        self.btn_refresh.clicked.connect(self.load_quarantine_data)
        self.btn_restore.clicked.connect(self.restore_selected)
        self.btn_delete.clicked.connect(self.delete_selected)

        self.load_quarantine_data()

    def load_quarantine_data(self):
        """Fetches items from database and populates table."""
        self.table.setRowCount(0)
        self.chk_select_all.setChecked(False) # Reset select all
        try:
            with sqlite3.connect("database/sentinelx.db") as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, original_path, threat_name, hash, timestamp FROM quarantine_records")
                records = cursor.fetchall()
                
                for row_idx, record in enumerate(records):
                    self.table.insertRow(row_idx)
                    
                    # Add Checkbox Widget
                    chk_widget = QWidget()
                    chk_layout = QHBoxLayout(chk_widget)
                    chk_layout.setContentsMargins(0, 0, 0, 0)
                    chk_layout.setAlignment(Qt.AlignCenter)
                    chk_box = QCheckBox()
                    chk_layout.addWidget(chk_box)
                    self.table.setCellWidget(row_idx, 0, chk_widget)
                    
                    for col_idx, value in enumerate(record):
                        item = QTableWidgetItem(str(value))
                        item.setFlags(item.flags() ^ Qt.ItemIsEditable) # Make read-only
                        self.table.setItem(row_idx, col_idx + 1, item)
        except Exception as e:
            print(f"Error loading quarantine data: {e}")

    def toggle_select_all(self, checked):
        for row in range(self.table.rowCount()):
            chk_widget = self.table.cellWidget(row, 0)
            if chk_widget:
                chk_box = chk_widget.findChild(QCheckBox)
                if chk_box:
                    chk_box.setChecked(checked)

    def get_selected_ids(self):
        selected_ids = []
        for row in range(self.table.rowCount()):
            chk_widget = self.table.cellWidget(row, 0)
            if chk_widget:
                chk_box = chk_widget.findChild(QCheckBox)
                if chk_box and chk_box.isChecked():
                    record_id = int(self.table.item(row, 1).text())
                    selected_ids.append(record_id)
        return selected_ids

    def restore_selected(self):
        record_ids = self.get_selected_ids()
        if not record_ids:
            QMessageBox.warning(self, "No Selection", "Please select at least one file to restore.")
            return

        reply = QMessageBox.question(self, "Confirm Restore", 
                                     f"Are you sure you want to restore {len(record_ids)} file(s)? They may be malicious.",
                                     QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            success_count = 0
            for r_id in record_ids:
                if self.quarantine_manager.restore_file(r_id):
                    success_count += 1
            
            QMessageBox.information(self, "Restore Complete", f"Successfully restored {success_count} out of {len(record_ids)} files.")
            self.load_quarantine_data()

    def delete_selected(self):
        record_ids = self.get_selected_ids()
        if not record_ids:
            QMessageBox.warning(self, "No Selection", "Please select at least one file to delete.")
            return

        reply = QMessageBox.question(self, "Confirm Deletion", 
                                     f"Are you sure you want to permanently delete {len(record_ids)} file(s)? This cannot be undone.",
                                     QMessageBox.Yes | QMessageBox.No)
        
        if reply == QMessageBox.Yes:
            success_count = 0
            for r_id in record_ids:
                if self.quarantine_manager.delete_record(r_id):
                    success_count += 1
                    
            QMessageBox.information(self, "Deletion Complete", f"Successfully deleted {success_count} out of {len(record_ids)} files.")
            self.load_quarantine_data()

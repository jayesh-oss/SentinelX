import os
import shutil
import logging
import sqlite3
from database.db_manager import DatabaseManager

class QuarantineManager:
    def __init__(self, quarantine_dir="quarantine"):
        self.quarantine_dir = quarantine_dir
        self.db = DatabaseManager()
        if not os.path.exists(self.quarantine_dir):
            os.makedirs(self.quarantine_dir)

    def quarantine_file(self, file_path, threat_name, file_hash):
        """Moves a detected file into the quarantine directory securely."""
        if not os.path.exists(file_path):
            return False

        file_name = os.path.basename(file_path)
        # Prevent collisions in quarantine
        quarantine_path = os.path.join(self.quarantine_dir, f"{file_hash}_{file_name}.isolated")
        
        try:
            # Move file, essentially destroying execution context and adding extension
            shutil.move(file_path, quarantine_path)

            # Log into database
            with sqlite3.connect(self.db.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT INTO quarantine_records (original_path, quarantine_path, hash, threat_name)
                    VALUES (?, ?, ?, ?)
                ''', (file_path, quarantine_path, file_hash, threat_name))
                conn.commit()

            logging.info(f"Successfully quarantined {file_path} to {quarantine_path}")
            return True
        except Exception as e:
            logging.error(f"Failed to quarantine {file_path}: {e}")
            # Could be locked by another process
            return False

    def restore_file(self, record_id):
        """Restores a file from quarantine back to its original path."""
        try:
            with sqlite3.connect(self.db.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT original_path, quarantine_path FROM quarantine_records WHERE id = ?", (record_id,))
                record = cursor.fetchone()

                if not record:
                    return False

                orig_path, quar_path = record

                if os.path.exists(quar_path):
                    # Ensure destination directory exists
                    os.makedirs(os.path.dirname(orig_path), exist_ok=True)
                    shutil.move(quar_path, orig_path)

                # Remove from DB
                cursor.execute("DELETE FROM quarantine_records WHERE id = ?", (record_id,))
                conn.commit()
                return True
        except Exception as e:
            logging.error(f"Failed to restore file: {e}")
            return False

    def delete_record(self, record_id):
        """Deletes a file permanently from quarantine."""
        try:
            with sqlite3.connect(self.db.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT quarantine_path FROM quarantine_records WHERE id = ?", (record_id,))
                record = cursor.fetchone()

                if record:
                    quar_path = record[0]
                    if os.path.exists(quar_path):
                        os.remove(quar_path)
                
                # Remove from DB
                cursor.execute("DELETE FROM quarantine_records WHERE id = ?", (record_id,))
                conn.commit()
                return True
        except Exception as e:
            logging.error(f"Failed to delete quarantined file: {e}")
            return False

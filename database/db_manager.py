import sqlite3
import os
import logging

class DatabaseManager:
    def __init__(self, db_path="database/sentinelx.db"):
        self.db_path = db_path
        os.makedirs(os.path.dirname(self.db_path) or '.', exist_ok=True)
        self._init_db()

    def _init_db(self):
        """Initializes the database schema if it doesn't exist."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                
                # Scan History
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS scan_history (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                        file_path TEXT,
                        scan_type TEXT,
                        result TEXT,
                        threat_name TEXT
                    )
                ''')
                
                # Hash Reputation Cache
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS hash_reputation (
                        hash TEXT PRIMARY KEY,
                        score INTEGER,
                        known_malware BOOLEAN,
                        last_checked DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                # Quarantine Records
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS quarantine_records (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        original_path TEXT,
                        quarantine_path TEXT,
                        hash TEXT,
                        threat_name TEXT,
                        timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                # VirusTotal Cache
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS vt_cache (
                        hash TEXT PRIMARY KEY,
                        positives INTEGER,
                        total INTEGER,
                        permalink TEXT,
                        last_checked DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')

                # Rule Metadata
                cursor.execute('''
                    CREATE TABLE IF NOT EXISTS rule_metadata (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        name TEXT UNIQUE,
                        description TEXT,
                        source TEXT,
                        version TEXT,
                        last_updated DATETIME DEFAULT CURRENT_TIMESTAMP
                    )
                ''')
                
                conn.commit()
                logging.info(f"Database initialized at {self.db_path}")
        except sqlite3.Error as e:
            logging.error(f"Failed to initialize database: {e}")

    def log_scan(self, file_path, scan_type, result, threat_name=None):
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO scan_history (file_path, scan_type, result, threat_name)
                VALUES (?, ?, ?, ?)
            ''', (file_path, scan_type, result, threat_name))
            conn.commit()

    def reset_statistics(self):
        """Clears the scan_history table to reset the dashboard counters."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM scan_history")
                # Also reset sqlite auto-increment sequence for cleaner IDs
                cursor.execute("DELETE FROM sqlite_sequence WHERE name='scan_history'")
                conn.commit()
                return True
        except sqlite3.Error as e:
            logging.error(f"Failed to reset statistics: {e}")
            return False

    def get_hash_reputation(self, file_hash):
        """Returns True if known malware, False if explicitly whitelisted, None if unknown."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT known_malware FROM hash_reputation WHERE hash = ?", (file_hash,))
                result = cursor.fetchone()
                return bool(result[0]) if result else None
        except sqlite3.Error:
            return None

    def set_hash_reputation(self, file_hash, is_malware):
        """Sets a hash as either malware (True) or whitelisted (False)."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO hash_reputation (hash, score, known_malware)
                    VALUES (?, 0, ?)
                ''', (file_hash, 1 if is_malware else 0))
                conn.commit()
        except sqlite3.Error as e:
            logging.error(f"Failed to set hash reputation: {e}")

# Testing logic if run as standalone
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    db = DatabaseManager()
    print("Database manager strictly created and instantiated schemas.")

import json
import sqlite3
import logging
import requests
from typing import Optional, Dict


class VirusTotalEngine:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        if not self.api_key:
            self._load_config()

    def _load_config(self):
        try:
            with open("database/config.json", "r") as f:
                config = json.load(f)
                self.api_key = config.get("vt_api_key", "")
        except FileNotFoundError:
            self.api_key = ""

    def update_key(self, new_key: str):
        self.api_key = new_key
        try:
            with open("database/config.json", "w") as f:
                json.dump({"vt_api_key": self.api_key}, f)
        except Exception as e:
            logging.error(f"Failed to save VT config: {e}")

    def check_hash_cache(self, file_hash: str) -> Optional[Dict]:
        try:
            with sqlite3.connect("database/sentinelx.db") as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT positives, total, permalink FROM vt_cache WHERE hash = ?", (file_hash,))
                row = cursor.fetchone()
                if row:
                    return {
                        "malicious": row[0],
                        "total": row[1],
                        "permalink": row[2]
                    }
        except Exception as e:
            logging.error(f"VT Cache read error: {e}")
        return None

    def _save_to_cache(self, file_hash: str, positives: int, total: int, permalink: str):
        try:
            with sqlite3.connect("database/sentinelx.db") as conn:
                cursor = conn.cursor()
                cursor.execute('''
                    INSERT OR REPLACE INTO vt_cache (hash, positives, total, permalink)
                    VALUES (?, ?, ?, ?)
                ''', (file_hash, positives, total, permalink))
                conn.commit()
        except Exception as e:
            logging.error(f"VT Cache write error: {e}")

    def lookup_hash(self, file_hash: str) -> Dict:
        cached = self.check_hash_cache(file_hash)
        if cached:
            return {"status": "cached", "data": cached}

        if not self.api_key:
            return {"status": "error", "error": "No API Key configured"}

        try:
            url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
            headers = {"x-apikey": self.api_key}
            response = requests.get(url, headers=headers, timeout=15)

            if response.status_code == 404:
                return {"status": "not_found", "data": None}
            response.raise_for_status()

            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            data = {
                "malicious": stats.get("malicious", 0),
                "total": sum(stats.values()),
                "permalink": f"https://www.virustotal.com/gui/file/{file_hash}"
            }
            self._save_to_cache(file_hash, data["malicious"], data["total"], data["permalink"])
            return {"status": "success", "data": data}
        except requests.exceptions.HTTPError as e:
            if e.response is not None and e.response.status_code == 404:
                return {"status": "not_found", "data": None}
            logging.error(f"VT API HTTP Error: {e}")
            return {"status": "error", "error": str(e)}
        except Exception as e:
            logging.error(f"VT API Error: {e}")
            return {"status": "error", "error": str(e)}

import vt
import json
import sqlite3
import logging
import asyncio
from typing import Optional, Dict

class VirusTotalEngine:
    def __init__(self, api_key: Optional[str] = None):
        self.api_key = api_key
        # We try to load it from a simple config file if not passed directly
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
        """Check local SQLite cache before hitting VT API to save rate limits."""
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
        """Looks up a hash against VirusTotal."""
        # 1. Check Cache first
        cached = self.check_hash_cache(file_hash)
        if cached:
            return {"status": "cached", "data": cached}

        if not self.api_key:
            return {"status": "error", "error": "No API Key configured"}

        # 2. Query API synchronously (using vt-py's sync wrapper mechanics or direct REST if asyncio is tricky in QThread)
        # Using a simple synchronous request via requests module is often safer in PySide threads, 
        # but since vt-py is inherently asyncio, we'll wrap it.
        try:
            result = asyncio.run(self._async_lookup(file_hash))
            if result and result.get("data"):
                self._save_to_cache(file_hash, result["data"]["malicious"], result["data"]["total"], result["data"]["permalink"])
            return result
        except Exception as e:
            logging.error(f"VT API Error: {e}")
            return {"status": "error", "error": str(e)}

    async def _async_lookup(self, file_hash: str) -> Dict:
        async with vt.Client(self.api_key) as client:
            try:
                # Get the file object
                file_obj = await client.get_object_async(f"/files/{file_hash}")
                stats = file_obj.last_analysis_stats
                
                return {
                    "status": "success",
                    "data": {
                        "malicious": stats.get('malicious', 0),
                        "total": sum(stats.values()),
                        "permalink": f"https://www.virustotal.com/gui/file/{file_hash}"
                    }
                }
            except vt.APIError as e:
                if e.code == "NotFoundError":
                    return {"status": "not_found", "data": None}
                raise e

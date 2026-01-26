import sqlite3
import requests
import time
import threading
from config import Config

class URLDatabase:
    def __init__(self):
        self._cache = {}
        self._cache_lock = threading.Lock()
        self._init_db()
        if self._is_empty():
            self.auto_fill_from_github()

    def _init_db(self):
        # Using Config.DB_PATH as established in config.py
        with sqlite3.connect(Config.DB_PATH) as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS local_intel (
                domain TEXT PRIMARY KEY,
                danger_level INTEGER,
                last_updated INTEGER
            )''')
            # Add index for faster lookups
            conn.execute('''CREATE INDEX IF NOT EXISTS idx_domain ON local_intel(domain)''')
            conn.commit()

    def _is_empty(self):
        with sqlite3.connect(Config.DB_PATH) as conn:
            return conn.execute("SELECT COUNT(*) FROM local_intel").fetchone()[0] == 0

    def auto_fill_from_github(self):
        print("🚀 Initializing Local Threat Database from Global Sources...")
        try:
            r = requests.get(Config.GITHUB_DB_URL, timeout=15)
            if r.status_code == 200:
                domains = [(line.strip().lower(), 100, int(time.time())) 
                           for line in r.text.splitlines() if line and not line.startswith('#')]
                with sqlite3.connect(Config.DB_PATH) as conn:
                    conn.executemany("INSERT OR REPLACE INTO local_intel VALUES (?, ?, ?)", domains)
                print(f"✅ Successfully loaded {len(domains)} known threats.")
        except Exception as e:
            print(f"⚠️ GitHub Sync Failed: {e}")

    def check_threat(self, domain):
        domain = domain.lower()
        
        # Check cache first
        with self._cache_lock:
            if domain in self._cache:
                return self._cache[domain]
        
        # Check database
        with sqlite3.connect(Config.DB_PATH) as conn:
            res = conn.execute("SELECT danger_level FROM local_intel WHERE domain = ?", (domain,)).fetchone()
            threat_level = res[0] if res else 0
            
            # Cache the result
            with self._cache_lock:
                self._cache[domain] = threat_level
                # Keep cache size manageable
                if len(self._cache) > 1000:
                    # Remove oldest entries
                    keys_to_remove = list(self._cache.keys())[:500]
                    for key in keys_to_remove:
                        del self._cache[key]
            
            return threat_level

db = URLDatabase()

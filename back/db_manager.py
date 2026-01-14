import sqlite3
import requests
import time
from config import Config

class URLDatabase:
    def __init__(self):
        self._init_db()
        if self._is_empty():
            self.auto_fill_from_github()

    def _init_db(self):
        with sqlite3.connect(Config.DB_PATH) as conn:
            conn.execute('''CREATE TABLE IF NOT EXISTS local_intel (
                domain TEXT PRIMARY KEY,
                danger_level INTEGER,
                last_updated INTEGER
            )''')

    def _is_empty(self):
        with sqlite3.connect(Config.DB_PATH) as conn:
            return conn.execute("SELECT COUNT(*) FROM local_intel").fetchone()[0] == 0

    def auto_fill_from_github(self):
        print("🚀 Initializing Local Threat Database...")
        try:
            r = requests.get(Config.GITHUB_DB_URL, timeout=15)
            if r.status_code == 200:
                domains = [(line.strip().lower(), 100, int(time.time())) 
                           for line in r.text.splitlines() if line and not line.startswith('#')]
                with sqlite3.connect(Config.DB_PATH) as conn:
                    conn.executemany("INSERT OR REPLACE INTO local_intel VALUES (?, ?, ?)", domains)
                print(f"✅ Loaded {len(domains)} known threats.")
        except Exception as e:
            print(f"⚠️ GitHub Sync Failed: {e}")

    def check_threat(self, domain):
        with sqlite3.connect(Config.DB_PATH) as conn:
            res = conn.execute("SELECT danger_level FROM local_intel WHERE domain = ?", (domain.lower(),)).fetchone()
            return res[0] if res else 0

    def save_threat(self, domain, level):
        with sqlite3.connect(Config.DB_PATH) as conn:
            conn.execute("INSERT OR REPLACE INTO local_intel VALUES (?, ?, ?)", 
                         (domain.lower(), level, int(time.time())))

db = URLDatabase()
# Database manager for my phishing detector
# This handles the database of bad websites
import sqlite3
import requests
import time
import threading
from config import Config

class URLDatabase:
    def __init__(self):
        # Set up cache and locks so it doesn't get messed up
        self._cache = {}
        self._cache_lock = threading.Lock()
        self._init_db()
        
        # If database is empty, download the bad websites list
        if self._is_empty():
            self.auto_fill_from_github()

    def _init_db(self):
        """
        Create the database table if it doesn't exist
        """
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
        """
        Check if the database has any data in it
        """
        with sqlite3.connect(Config.DB_PATH) as conn:
            return conn.execute("SELECT COUNT(*) FROM local_intel").fetchone()[0] == 0

    def auto_fill_from_github(self):
        """
        Download the list of known bad websites from GitHub
        """
        print("🚀 Getting dangerous websites from the internet...")
        try:
            r = requests.get(Config.GITHUB_DB_URL, timeout=15)
            if r.status_code == 200:
                # Parse the list and add to database
                domains = [(line.strip().lower(), 100, int(time.time())) 
                           for line in r.text.splitlines() if line and not line.startswith('#')]
                with sqlite3.connect(Config.DB_PATH) as conn:
                    conn.executemany("INSERT OR REPLACE INTO local_intel VALUES (?, ?, ?)", domains)
                print(f"✅ Loaded {len(domains)} bad websites!")
        except Exception as e:
            print(f"⚠️ Oops, couldn't download: {e}")

    def check_threat(self, domain):
        """
        Check if a website is in our bad list
        """
        domain = domain.lower()
        
        # Check cache first (faster!)
        with self._cache_lock:
            if domain in self._cache:
                return self._cache[domain]
        
        # Check database
        with sqlite3.connect(Config.DB_PATH) as conn:
            res = conn.execute("SELECT danger_level FROM local_intel WHERE domain = ?", (domain,)).fetchone()
            threat_level = res[0] if res else 0
            
            # Cache the result for next time
            with self._cache_lock:
                self._cache[domain] = threat_level
                # Keep cache from getting too big
                if len(self._cache) > 1000:
                    # Remove oldest entries
                    keys_to_remove = list(self._cache.keys())[:500]
                    for key in keys_to_remove:
                        del self._cache[key]
            
            return threat_level

# Create the database instance that everyone uses
db = URLDatabase()

import os
import time

class Config:
    HOST = '127.0.0.1'
    PORT = 5000
    PHISHING_THRESHOLD = 70
    
    # DATABASE CONFIG
    DB_PATH = os.path.join(os.path.dirname(__file__), "phish_cache.db")
    # GitHub database for first-run initialization
    GITHUB_DB_URL = "https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt"
    
    # BRAND PROTECTION
    PROTECTED_BRANDS = {
        'paypal': 'paypal.com', 'google': 'google.com', 'microsoft': 'microsoft.com',
        'amazon': 'amazon.com', 'netflix': 'netflix.com', 'apple': 'apple.com'
    }

    # THREAT LEXICON
    LEXICON = {
        'urgency': ['urgent', 'verify', 'suspended', 'action required', 'immediate'],
        'financial': ['invoice', 'refund', 'payment', 'transaction', 'credits'],
        'security': ['unauthorized', 'detected', 'security alert', 'compromised']
    }

    @classmethod
    def should_update_db(cls):
        if not os.path.exists(cls.DB_PATH): return True
        return (time.time() - os.path.getmtime(cls.DB_PATH)) > 86400 # 24 hours
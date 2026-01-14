import requests
from urllib.parse import urlparse

class ThreatIntel:
    API_URL = "https://phishstats.info:2053/api/v1/"

    @staticmethod
    def get_dangerosity(url):
        domain = urlparse(url).netloc.lower()
        try:
            # Check specific URL in global database
            r = requests.get(f"{ThreatIntel.API_URL}?_where=(url,eq,{url})", timeout=5)
            if r.status_code == 200 and len(r.json()) > 0:
                return "MALICIOUS", 100
            
            # Check if domain itself is flagged
            r_dom = requests.get(f"{ThreatIntel.API_URL}?_where=(domain,eq,{domain})", timeout=5)
            if r_dom.status_code == 200 and len(r_dom.json()) > 0:
                return "SUSPICIOUS", 70
                
            return "CLEAN", 0
        except:
            return "UNKNOWN", 0
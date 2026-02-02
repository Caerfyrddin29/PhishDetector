import requests
from urllib.parse import urlparse

class ThreatIntel:
    API_URL = "https://phishstats.info:2053/api/v1/"

    @staticmethod
    def get_dangerosity(url):
        domain = urlparse(url).netloc.lower()
        try:
            # Check specific URL in global database
            r = requests.get(f"{ThreatIntel.API_URL}?_where=(url,eq,{url})", timeout=1.5)
            if r.status_code == 200:
                try:
                    data = r.json()
                    if len(data) > 0:
                        return "MALICIOUS", 25  # 25% for confirmed malicious
                except (ValueError, KeyError):
                    pass
            
            # Check if domain itself is flagged
            r_dom = requests.get(f"{ThreatIntel.API_URL}?_where=(domain,eq,{domain})", timeout=1.5)
            if r_dom.status_code == 200:
                try:
                    data = r_dom.json()
                    if len(data) > 0:
                        return "SUSPICIOUS", 15  # 15% for suspicious domain
                except (ValueError, KeyError):
                    pass
                
            return "CLEAN", 0
        except requests.exceptions.Timeout:
            return "TIMEOUT", 0
        except requests.exceptions.RequestException:
            return "UNKNOWN", 0
        except:
            return "ERROR", 0
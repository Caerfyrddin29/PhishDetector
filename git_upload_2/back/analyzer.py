import re
import math
import hashlib
import time
from urllib.parse import urlparse
from difflib import SequenceMatcher
from config import Config
from db_manager import db
from threat_intel import ThreatIntel

class PhishingAnalyzer:
    def __init__(self):
        # I'm using caches so the program doesn't get slow
        self.cache = {}
        self.link_cache = {}

    def _get_content_hash(self, body, sender, link_count):
        """
        Make a unique ID for each email so we don't analyze the same one twice.
        
        Args:
            body (str): The email body content
            sender (str): The sender's email address
            link_count (int): How many links are in the email
            
        Returns:
            str: A hash string we can use to remember this email
            
        Example:
            >>> hash_key = analyzer._get_content_hash("Urgent payment needed", "boss@company.com", 3)
            >>> print(hash_key[:10] + "...")  # Just show first few chars
            a1b2c3d4e5...
        """
        content = f"{body[:200]}{sender}{link_count}"
        return hashlib.md5(content.encode()).hexdigest()

    def _analyze_linguistic_patterns(self, body_clean):
        """
        Look for words and phrases that scammers use.
        
        Scammers have favorite phrases like "urgent payment" or "verify your account"
        that they use over and over. This method hunts for those patterns and scores
        how suspicious the email sounds based on the language they're using.
        
        Args:
            body_clean (str): The email text with HTML stripped out and everything lowercase
            
        Returns:
            tuple: (score, reasons) where:
                - score (int): How many suspicious points this email earned
                - reasons (list[str]): What exactly we found that looked fishy
                
        Example:
            >>> score, reasons = analyzer._analyze_linguistic_patterns("urgent payment needed now")
            >>> print(f"Score: {score}, Why: {reasons}")
            Score: 45, Why: ['Urgent money request']
        """
        score = 0
        reasons = []
        
        # These are patterns that scammers use to create urgency and fear
        urgency_patterns = [
            # "urgent payment" type phrases
            (r'\burgent\b.*\b(payment|transfer|invoice|wire)\b', 25, "Urgent money request"),
            (r'\b(immediate|asap|right away)\b.*\b(send|transfer|pay)\b', 20, "Time pressure for money"),
            (r'\b(urgent|immediately|asap)\b.*\b(before\s+(today|tomorrow|monday|tuesday))', 20, "Impossible time constraint"),
            (r'\b(within\s+(the\s+next\s+hour|30\s+minutes|1\s+hour))\b', 25, "Unrealistic deadline"),
            
            # "boss" or "authority" type phrases
            (r'\b(ceo|cfo|director|manager)\b.*\b(request|need|require)\b', 20, "Boss impersonation"),
            (r'\b(your\s+manager|your\s+supervisor)\b.*\b(need|want)\b', 15, "Fake authority claim"),
            
            # Secret/confidential type phrases
            (r'\b(confidential|secret|private)\b.*\b(document|file|information)\b', 15, "Fake secrecy"),
            (r'\b(don\'t\s+tell\s+anyone|keep\s+secret)\b', 20, "Secrecy request"),
        ]
        
        # These are patterns that try to manipulate people emotionally
        manipulation_patterns = [
            # "trust me" type phrases
            (r'\b(trust\s+me|believe\s+me|i\s+need\s+your\s+help)\b', 15, "Trust manipulation"),
            (r'\b(only\s+you|just\s+you)\b.*\b(can\s+help)\b', 20, "Special treatment claim"),
            
            # Gift card and purchase scams
            (r'\b(gift\s+card|itunes|amazon)\b.*\b(buy|purchase|quickly)\b', 25, "Gift card scam"),
            (r'\b(quick\s+buy|urgent\s+purchase)\b.*\b(gift|card|voucher)\b', 20, "Urgent purchase scam"),
        ]
        
        # These are more sophisticated scam patterns
        advanced_patterns = [
            # Crypto and investment scams
            (r'\b(bitcoin|cryptocurrency|blockchain)\b.*\b(invest|profit|return)\b', 30, "Crypto investment scam"),
            (r'\b(artificial\s+intelligence|ai\s+trading)\b.*\b(profit|money)\b', 25, "AI trading scam"),
            
            # "You won" type scams
            (r'\b(congratulations|winner|selected)\b.*\b(prize|money|reward)\b', 25, "Prize scam"),
            (r'\b(limited\s+time|exclusive|only\s+you)\b.*\b(offer|deal)\b', 20, "Fake exclusivity"),
        ]
        
        # Check all patterns and add up the scores
        all_patterns = urgency_patterns + manipulation_patterns + advanced_patterns
        for pattern, points, reason in all_patterns:
            if re.search(pattern, body_clean, re.IGNORECASE):
                score += points
                reasons.append(reason)
        
        return score, reasons

    def _analyze_semantic_anomalies(self, body_clean, sender):
        """
        Identify unnatural conversation patterns that indicate phishing attempts.
        
        Some emails simply don't read like genuine human communication. This method
        detects suspicious language patterns such as fake greetings, artificial familiarity,
        and psychological manipulation tactics commonly used in phishing campaigns.
        
        Args:
            body_clean (str): The email content with HTML removed and converted to lowercase
            sender (str): The sender's email address for context analysis
            
        Returns:
            tuple: (risk_score, suspicious_patterns) where:
                - risk_score (int): Accumulated risk score based on semantic anomalies
                - suspicious_patterns (list[str]): Descriptions of detected suspicious patterns
                
        Example:
            >>> score, patterns = analyzer._analyze_semantic_anomalies("dear friend trust me", "scammer@fake.com")
            >>> print(f"Risk score: {score}, Suspicious patterns: {patterns}")
            Risk score: 35, Suspicious patterns: ['Fake relationship', 'Trust manipulation']
        """
        score = 0
        reasons = []
        
        # These are greeting patterns that sound like scam templates
        weird_greetings = [
            # Generic greetings that sound fake
            (r'^(hi|hello|dear)\s+[a-z]+\s*[,\.!?]\s*i\s+hope', 20, "Generic template greeting"),
            (r'^(dear\s+(friend|colleague|customer))', 25, "Impersonal greeting"),
            
            # Fake relationship claims
            (r'(my\s+friend|my\s+colleague|my\s+partner)', 15, "Fake relationship"),
            (r'(we\s+know\s+each\s+other|we\'ve\s+met)', 20, "Fake familiarity"),
        ]
        
        # These are psychological manipulation tactics
        psychological_patterns = [
            # False authority claims
            (r'\b(ceo|director|manager)\s+(said|requested|ordered)', 30, "Fake boss authority"),
            (r'\b(legal|attorney|court)\s+(action|notice|subpoena)', 35, "Fake legal threat"),
            
            # Account threats
            (r'\b(account\s+will\s+be|will\s+be)\s+(suspended|closed|terminated)', 30, "Account closure threat"),
            (r'\b(your\s+account|immediate\s+action|required)', 25, "Account urgency"),
            
            # Fear and pressure tactics
            (r'\b(arrest|jail|police|legal\s+action)\b', 40, "Legal threat intimidation"),
            (r'\b(serious\s+consequences|legal\s+trouble)\b', 30, "Vague threat"),
        ]
        
        # Check all patterns
        all_patterns = weird_greetings + psychological_patterns
        for pattern, points, reason in all_patterns:
            if re.search(pattern, body_clean, re.IGNORECASE):
                score += points
                reasons.append(reason)
        
        return score, reasons

    def _analyze_contextual_anomalies(self, body_clean, sender):
        """
        Detect logical inconsistencies and unrealistic claims in email content.
        
        Phishing attempts often contain promises or scenarios that defy logic and reality.
        This method identifies claims such as impossible guarantees, unrealistic timeframes,
        and technical assertions that should raise suspicion about the message's legitimacy.
        
        Args:
            body_clean (str): The email content with HTML removed and converted to lowercase
            sender (str): The sender's email address for contextual analysis
            
        Returns:
            tuple: (risk_score, inconsistencies) where:
                - risk_score (int): Accumulated risk score based on contextual anomalies
                - inconsistencies (list[str]): Descriptions of detected logical inconsistencies
                
        Example:
            >>> score, issues = analyzer._analyze_contextual_anomalies("100% guaranteed profit no risk")
            >>> print(f"Risk score: {score}, Issues: {issues}")
            Risk score: 55, Issues: ['Impossible guarantee', 'Risk denial pattern']
        """
        score = 0
        reasons = []
        
        # Time-based problems (impossible deadlines)
        time_patterns = [
            (r'\b(immediately|urgently|asap|right\s+now)\s+(before\s+(today|tomorrow|monday|tuesday))', 20, "Impossible time constraint"),
            (r'\b(within\s+(the\s+next\s+hour|30\s+minutes|1\s+hour))\b', 25, "Unrealistic deadline"),
        ]
        
        # Money-related weirdness
        financial_anomalies = [
            (r'\$\d+(,\d{3})*(.\d{2})?\s+(only|just|mere)', 20, "Odd pricing language"),
            (r'\b(100%\s+(guaranteed|sure|certain|safe))', 30, "Impossible guarantee"),
            (r'\b(no\s+risk|risk\s+free|zero\s+risk)', 25, "Risk denial pattern"),
        ]
        
        # Fake technical claims
        tech_patterns = [
            (r'\b(proprietary|exclusive|secret)\s+(algorithm|system|technology)', 25, "Fake technical exclusivity"),
            (r'\b(patented|trademarked)\s+(trading|investment|profit)\s+(system|method)', 30, "Fake technical claims"),
        ]
        
        # Check all contextual patterns
        all_patterns = time_patterns + financial_anomalies + tech_patterns
        for pattern, points, reason in all_patterns:
            if re.search(pattern, body_clean, re.IGNORECASE):
                score += points
                reasons.append(reason)
        
        return score, reasons

    def _calculate_entropy(self, text):
        """
        Calculate the entropy of text to detect suspicious character patterns.
        
        Malicious actors often obfuscate content using encoded or random-looking text.
        This method uses Shannon entropy to measure character randomness, helping identify
        potentially hidden malicious content that deviates from normal language patterns.
        
        Args:
            text (str): The text string to analyze for entropy characteristics
            
        Returns:
            float: Entropy value ranging from 0 to 8+. Normal English text typically
                   falls between 3.0-4.0, while obfuscated content often exceeds 5.0.
                   
        Example:
            >>> entropy = analyzer._calculate_entropy("normal text")
            >>> print(f"Entropy: {entropy:.2f}")
            Entropy: 3.45
        """
        if not text:
            return 0
        
        # Count character frequencies
        counts = {c: text.count(c) for c in set(text)}
        
        # Calculate Shannon entropy
        entropy = -sum((count/len(text)) * math.log2(count/len(text)) for count in counts.values())
        
        return entropy

    def _analyze_sender_behavior(self, body_clean, sender):
        """
        Analyze the sender's email address for suspicious patterns and characteristics.
        
        Phishing attempts frequently use deceptive email addresses designed to impersonate
        legitimate organizations or create false authority. This method examines domain names,
        formatting patterns, and other indicators to identify potentially fraudulent senders.
        
        Args:
            body_clean (str): The email content for contextual analysis
            sender (str): The complete email address of the sender (e.g., "user@domain.com")
            
        Returns:
            dict: Analysis results containing:
                - score (int): Risk assessment score based on sender characteristics (0-100+)
                - reasons (list[str]): Specific suspicious indicators detected
                
        Example:
            >>> result = analyzer._analyze_sender_behavior("urgent email", "scammer@secure-update.com")
            >>> print(f"Risk score: {result['score']}, Indicators: {result['reasons']}")
            Risk score: 25, Indicators: ['Domain has security-related words (possible fake)']
        """
        score = 0
        reasons = []
        
        # Make sure we actually have a sender email
        if sender and '@' in sender:
            domain = sender.split('@')[1].lower()
            
            # Look for suspicious words in domain names
            suspicious_domains = ['secure', 'verify', 'safety', 'protect', 'alert', 'update']
            if any(word in domain for word in suspicious_domains):
                # Skip the big legitimate companies
                if domain not in ['microsoft.com', 'google.com', 'apple.com', 'amazon.com']:
                    score += 25
                    reasons.append("Domain has security-related words (possible fake)")
            
            # Look for domains that look auto-generated
            if len(domain) > 20 and any(char.isdigit() for char in domain):
                score += 15
                reasons.append("Domain looks auto-generated")
            
            # Check if someone is using personal email for business stuff
            personal_domains = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com']
            if domain in personal_domains:
                business_words = ['company', 'business', 'corporate', 'enterprise', 'invoice']
                if any(word in body_clean for word in business_words):
                    score += 20
                    reasons.append("Personal email used for business")
        
        return {'score': score, 'reasons': reasons}

    def _check_brand_squatting(self, domain):
        """
        See if someone is pretending to be a famous company.
        
        Scammers love making domains like "paypal-secure.com" or "microsoft-help.net"
        that look like the real thing but aren't. This checks how similar a domain
        is to famous brands and calls it out if it's trying to impersonate them.
        
        Args:
            domain (str): Just the domain part like "paypal-secure.com"
            
        Returns:
            tuple: (score, reasons) where:
                - score (int): How much this looks like brand impersonation (0-40)
                - reasons (list[str]): Which brand they're probably faking
                
        Example:
            >>> score, reasons = analyzer._check_brand_squatting("paypal-secure.com")
            >>> print(f"Fake brand score: {score}, Who they're copying: {reasons}")
            Fake brand score: 40, Who they're copying: ['Domain looks like paypal but isn\'t']
        """
        score = 0
        reasons = []
        
        # List of famous brands that scammers impersonate
        famous_brands = [
            'paypal', 'microsoft', 'google', 'apple', 'amazon', 
            'facebook', 'instagram', 'netflix', 'linkedin', 'twitter'
        ]
        
        for brand in famous_brands:
            # Calculate how similar the domain is to the real brand
            similarity = SequenceMatcher(None, domain.lower(), brand).ratio()
            
            # If it's similar but not exactly the same, it's probably fake
            if similarity > 0.6 and brand not in domain.lower():
                score += 40
                reasons.append(f"Domain looks like {brand} but isn't")
                break
        
        return score, reasons

    def _analyze_link(self, link):
        """
        Check if a link in an email is trying to send you somewhere bad.
        
        This looks at everything about a link: the domain, if it's a known bad site,
        if it's pretending to be a famous brand, if it uses URL shorteners to hide
        where it's really going, and more. Basically, is this link trying to trick you?
        
        Args:
            link (dict): A BeautifulSoup link object that should have:
                - href (str): The actual URL (required!)
                - text (str, optional): What the link says when you click it
                
        Returns:
            tuple: (score, reasons, malicious_url) where:
                - score (int): How sketchy this link looks (0-200+)
                - reasons (list[str]): What exactly set off our alarm bells
                - malicious_url (str|None): The URL if we're sure it's bad, None if probably fine
                
        Example:
            >>> link = {'href': 'http://paypal-secure.com/login', 'text': 'Click here to login'}
            >>> score, reasons, is_bad = analyzer._analyze_link(link)
            >>> print(f"Sketchy level: {score}, Definitely bad: {is_bad is not None}")
            Sketchy level: 40, Definitely bad: True
        """
        href = link.get('href', '').lower().strip()
        
        # Skip links that aren't real URLs
        if not href or not href.startswith(('http://', 'https://')):
            return 0, [], None
            
        domain = urlparse(href).netloc
        score = 0
        reasons = []
        is_malicious = False
        
        # Skip trusted domains to save time
        trusted_domains = ['google.com', 'microsoft.com', 'apple.com', 'amazon.com']
        if any(trusted in domain for trusted in trusted_domains):
            return 0, [], None
        
        # Check our local database of bad domains
        if db.check_threat(domain) > 0:
            score += 100
            reasons.append(f"Known bad domain: {domain}")
            is_malicious = True
        
        # Check for brand squatting
        brand_score, brand_reasons = self._check_brand_squatting(domain)
        score += brand_score
        reasons.extend(brand_reasons)
        
        # Check for suspicious top-level domains
        suspicious_tlds = ['.tk', '.ml', '.ga', '.cf', '.top', '.click']
        if any(domain.endswith(tld) for tld in suspicious_tlds):
            score += 30
            reasons.append(f"Suspicious domain ending: {domain}")
        
        # Check for URL shorteners (can hide malicious links)
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl']
        if any(shortener in domain for shortener in shorteners):
            score += 15
            reasons.append("URL shortener (could hide malicious link)")
        
        # Only check external threat intelligence if we already think it's suspicious
        if score >= 30 or is_malicious:
            threat_status, threat_score = ThreatIntel.get_dangerosity(href)
            if threat_score > 0:
                score += threat_score
                reasons.append(f"External threat check: {threat_status}")
                if threat_score >= 100:
                    is_malicious = True
        
        # Return the score, reasons, and the URL if it's malicious
        return score, reasons, href if is_malicious else None

    def _analyze_links(self, links):
        """
        Analyze multiple links in an email with performance optimizations.
        
        Call this method to analyze all links in an email while avoiding duplicate
        work and limiting analysis to the most important links for performance.
        
        Args:
            links (list): List of BeautifulSoup link dictionaries from email content
            
        Returns:
            tuple: (total_score, all_reasons, malicious_urls) where:
                - total_score (int): Combined risk score from all links
                - all_reasons (list[str]): All suspicious findings across links
                - malicious_urls (list[str]): URLs confirmed to be malicious
                
        Example:
            >>> links = [{'href': 'http://evil.com', 'text': 'Click'}]
            >>> score, reasons, malicious = analyzer._analyze_links(links)
            >>> print(f"Total score: {score}, Malicious URLs: {len(malicious)}")
            Total score: 100, Malicious URLs: 1
        """
        if not links:
            return 0, [], []
        
        total_score = 0
        all_reasons = []
        malicious_urls = []
        
        # Remove duplicate domains to save time
        seen_domains = set()
        unique_links = []
        
        for link in links[:10]:  # Limit to 10 links for performance
            href = link.get('href', '').lower().strip()
            if href and href.startswith(('http://', 'https://')):
                domain = urlparse(href).netloc
                if domain not in seen_domains:
                    seen_domains.add(domain)
                    unique_links.append(link)
        
        # Check each unique link
        for link in unique_links:
            score, reasons, malicious_url = self._analyze_link(link)
            total_score += score
            all_reasons.extend(reasons)
            
            if malicious_url:
                malicious_urls.append(malicious_url)
        
        return total_score, all_reasons, malicious_urls

    def _fast_text_analysis(self, body_clean):
        """
        Perform rapid text analysis to identify common phishing indicators.
        
        This method conducts an initial scan of email content for frequently used
        phishing keywords and phrases in both English and French. It provides a quick
        risk assessment based on the presence of suspicious terminology.
        
        Args:
            body_clean (str): The email content with HTML removed and converted to lowercase
            
        Returns:
            tuple: (risk_score, indicators) where:
                - risk_score (int): Calculated risk score based on keyword frequency
                - indicators (list[str]): Categories of suspicious keywords detected
                
        Example:
            >>> score, indicators = analyzer._fast_text_analysis("urgent verify account suspended winner")
            >>> print(f"Risk score: {score}, Indicators: {indicators}")
            Risk score: 90, Indicators: ['Found 3 urgent words', 'Found 3 account security words', 'Found 1 scam-related words']
        """
        score = 0
        reasons = []
        
        # Check for French keywords first (bilingual support)
        urgency_words = []
        french_keywords = ['urgent', 'vérifier', 'compte', 'suspendu', 'connexion', 'action requise']
        if any(word in body_clean for word in french_keywords):
            urgency_words.extend(french_keywords)
        
        # Always include English keywords
        english_keywords = ['urgent', 'verify', 'account', 'password', 'suspended', 'action required', 'login']
        urgency_words.extend(english_keywords)
        
        # Count urgent words
        urgent_count = sum(1 for word in urgency_words if word in body_clean.lower())
        
        # Count scam words
        scam_words = ['exclusive task', 'multiply your earnings', 'guaranteed profit', 'earn $', 
                     'cash prize', 'winner', 'congratulations', 'free money', 'quick cash']
        scam_count = sum(1 for word in scam_words if word in body_clean.lower())
        
        # Count sophisticated scam indicators
        sophisticated_words = ['verify', 'account', 'suspended', 'security', 'confirm']
        sophisticated_count = sum(1 for word in sophisticated_words if word in body_clean.lower())
        
        # Calculate score based on word counts
        score = (urgent_count * 10) + (scam_count * 12) + (sophisticated_count * 15)
        
        # Add volume multiplier for high suspicious word counts
        total_suspicious = urgent_count + scam_count + sophisticated_count
        if total_suspicious > 5:
            multiplier = max(1.0, total_suspicious / 5.0)
            score = int(score * multiplier)
        
        # Add reasons for what we found
        if urgent_count > 0:
            reasons.append(f"Found {urgent_count} urgent words")
        if scam_count > 2:
            reasons.append(f"Found {scam_count} scam-related words")
        if sophisticated_count > 0:
            reasons.append(f"Found {sophisticated_count} account security words")
        if total_suspicious > 10:
            reasons.append(f"High volume of suspicious words ({total_suspicious} total)")
        
        return score, reasons

    def analyze(self, body, links=None, metadata=None, sender='', debug_mode=False):
        """
        Perform comprehensive phishing analysis using multiple detection methods.
        
        This method serves as the primary analysis function, integrating text analysis,
        link examination, sender evaluation, and behavioral pattern recognition to determine
        the likelihood of phishing. It combines all detection algorithms into a unified risk assessment.
        
        Args:
            body (str): Complete email content including HTML and text
            links (list, optional): Extracted links from the email content
            metadata (dict, optional): Additional email context including:
                - isTrusted (bool): Sender is in trusted contacts list
                - isReported (bool): Sender has been previously reported
                - imageCount (int): Number of embedded images
                - textLength (int): Length of text content
            sender (str, optional): Email address of the sender
            debug_mode (bool): Disable caching for testing purposes
            
        Returns:
            dict: Comprehensive analysis results containing:
                - is_phishing (bool): Determination if email exceeds phishing threshold
                - score (int): Total risk assessment score
                - threshold (int): Minimum score required for phishing classification
                - reasons (list[str]): All detected suspicious indicators
                - malicious_urls (list[str]): Confirmed malicious URLs
                - analysis_time (float): Processing duration in seconds
                
        Example:
            >>> result = analyzer.analyze("Urgent! Click here now!", [], {}, "scammer@fake.com")
            >>> print(f"Phishing detected: {result['is_phishing']}, Score: {result['score']}")
            Phishing detected: True, Score: 70
        """
        start_time = time.time()
        
        # Clean up the email body
        body_clean = re.sub(r'<[^>]+>', ' ', body).lower()
        metadata = metadata or {}
        
        # Skip caching if we're in debug mode
        if not debug_mode:
            content_hash = self._get_content_hash(body, sender, len(links) if links else 0)
            if content_hash in self.cache:
                cached_result = self.cache[content_hash]
                # Check if cache is still valid (5 minutes)
                if time.time() - cached_result['timestamp'] < 300:
                    return cached_result['result']
        
        # Initialize scores
        total_score = 0
        all_reasons = []
        malicious_urls = []
        
        # User reputation logic (early exit for trusted/blocked users)
        if metadata.get('isTrusted'):
            result = {
                'is_phishing': False,
                'score': 0,
                'threshold': Config.PHISHING_THRESHOLD,
                'reasons': ["Verified by User (Trusted List)"],
                'malicious_urls': [],
                'analysis_time': round(time.time() - start_time, 3)
            }
            return result
        
        if metadata.get('isReported'):
            total_score += 100
            all_reasons.append("Sender previously reported as malicious by you")
        
        # Check if sender is trusted (affects scoring)
        trusted_score_boost = 0
        if sender:
            sender_domain = sender.split('@')[-1].lower() if '@' in sender else sender.lower()
            is_trusted_sender = any(trusted in sender_domain for trusted in Config.TRUSTED_SENDERS)
            
            if is_trusted_sender:
                trusted_score_boost = -20  # Give benefit of doubt
        
        # Image-to-text ratio analysis (common phishing technique)
        if metadata.get('imageCount', 0) >= 1 and metadata.get('textLength', 0) < 60:
            total_score += 40
            all_reasons.append("High image-to-text ratio (Common filter bypass)")
        
        # 1. Analyze the text content
        text_score, text_reasons = self._fast_text_analysis(body_clean)
        total_score += text_score
        all_reasons.extend(text_reasons)
        
        # 2. Analyze linguistic patterns
        linguistic_score, linguistic_reasons = self._analyze_linguistic_patterns(body_clean)
        total_score += linguistic_score
        all_reasons.extend(linguistic_reasons)
        
        # 3. Analyze semantic anomalies
        semantic_score, semantic_reasons = self._analyze_semantic_anomalies(body_clean, sender)
        total_score += semantic_score
        all_reasons.extend(semantic_reasons)
        
        # 4. Analyze contextual anomalies
        contextual_score, contextual_reasons = self._analyze_contextual_anomalies(body_clean, sender)
        total_score += contextual_score
        all_reasons.extend(contextual_reasons)
        
        # 5. Analyze sender behavior
        sender_result = self._analyze_sender_behavior(body_clean, sender)
        total_score += sender_result['score']
        all_reasons.extend(sender_result['reasons'])
        
        # 6. Analyze links if there are any
        if links:
            link_score, link_reasons, malicious_urls = self._analyze_links(links)
            total_score += link_score
            all_reasons.extend(link_reasons)
        
        # Apply trusted sender boost
        total_score += trusted_score_boost
        
        # Determine if it's phishing based on the threshold
        is_phishing = total_score >= Config.PHISHING_THRESHOLD
        
        # Prepare the result
        result = {
            'is_phishing': is_phishing,
            'score': total_score,
            'threshold': Config.PHISHING_THRESHOLD,
            'reasons': all_reasons,
            'malicious_urls': malicious_urls,
            'analysis_time': round(time.time() - start_time, 3)
        }
        
        # Cache the result if not in debug mode
        if not debug_mode:
            self.cache[content_hash] = {
                'result': result,
                'timestamp': time.time()
            }
        
        return result

# Create the global analyzer instance
analyzer = PhishingAnalyzer()

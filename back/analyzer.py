import re
import math
import concurrent.futures
import hashlib
import time
from urllib.parse import urlparse
from difflib import SequenceMatcher
from config import Config
from db_manager import db
from threat_intel import ThreatIntel

class PhishingAnalyzer:
    def __init__(self):
        self.cache = {}
        self.link_cache = {}

    def _get_content_hash(self, body, sender, link_count):
        """Create hash for content-based caching"""
        # Include more context for better cache hits but avoid over-caching
        content = f"{body[:200]}{sender}{link_count}"  # Reduced to 200 chars for more variation
        return hashlib.md5(content.encode()).hexdigest()

    def _analyze_linguistic_patterns(self, body_clean):
        """Advanced linguistic analysis inspired by Microsoft/Proofpoint techniques"""
        score = 0
        reasons = []
        
        # 1. BEC-style linguistic patterns (Microsoft approach)
        bec_patterns = [
            # Authority and urgency combinations
            (r'\b(urgent|immediate|asap)\b.*\b(payment|transfer|invoice|wire)\b', 25, "BEC urgency + financial"),
            (r'\b(ceo|cfo|director|manager)\b.*\b(request|need|require)\b', 20, "Executive impersonation"),
            
            # Unusual request patterns
            (r'\b(gift card|purchase|buy)\b.*\b(quickly|urgent|asap)\b', 25, "Urgent purchase request"),
            (r'\b(confidential|secret|private)\b.*\b(document|file|information)\b', 15, "Information request"),
            
            # Conversation manipulation
            (r'\b(can you|could you)\b.*\b(quickly|now|asap)\b', 15, "Manipulative request"),
            (r'\b(only you|trust you)\b.*\b(help|assist)\b', 20, "Trust exploitation"),
        ]
        
        # 2. Sophisticated social engineering (Proofpoint approach)
        social_patterns = [
            # Professional context abuse
            (r'\b(client|customer|vendor)\b.*\b(issue|problem|emergency)\b', 20, "Business context abuse"),
            (r'\b(account|verification|security)\b.*\b(update|confirm|verify)\b', 25, "Security impersonation"),
            
            # Time pressure tactics
            (r'\b(closing|end of day|today)\b.*\b(need|require|must)\b', 20, "Time pressure"),
            (r'\b(weekend|after hours|urgent)\b.*\b(response|reply)\b', 15, "Off-hours pressure"),
        ]
        
        # 3. Advanced scam indicators (Industry best practices)
        advanced_patterns = [
            # Technical sophistication
            (r'\b(blockchain|cryptocurrency|bitcoin|ethereum)\b.*\b(invest|opportunity|profit)\b', 30, "Crypto investment scam"),
            (r'\b(artificial intelligence|ai|machine learning)\b.*\b(trading|profit|return)\b', 25, "AI trading scam"),
            
            # Emotional manipulation
            (r'\b(congratulations|winner|selected)\b.*\b(exclusive|special|vip)\b', 25, "Emotional manipulation"),
            (r'\b(limited|exclusive|only)\b.*\b(available|spots|time)\b', 20, "Artificial scarcity"),
        ]
        
        # Check all patterns
        all_patterns = bec_patterns + social_patterns + advanced_patterns
        for pattern, points, reason in all_patterns:
            if re.search(pattern, body_clean, re.IGNORECASE):
                score += points
                reasons.append(reason)
        
        return score, reasons

    def _analyze_semantic_anomalies(self, body_clean, sender):
        """Next-gen semantic analysis that goes beyond industry standards"""
        score = 0
        reasons = []
        
        # 1. CONVERSATIONAL ANOMALY DETECTION (Beyond Microsoft)
        conversation_patterns = [
            # Unusual greeting patterns
            (r'^(hi|hello|dear)\s+[a-z]+\s*[,\.!?]\s*i\s+hope', 20, "Generic greeting + hope (scam template)"),
            (r'^(dear\s+(friend|colleague|customer))', 25, "Impersonal formal greeting"),
            
            # Sudden relationship establishment
            (r'(my\s+friend|my\s+colleague|my\s+partner)', 15, "Fake relationship claim"),
            (r'(trust\s+me|believe\s+me|i\s+need\s+your\s+help)', 20, "Trust manipulation"),
            
            # Abnormal politeness (overcompensation)
            (r'(respectfully|cordially|best\s+regards)\s+(immediately|urgent|asap)', 25, "Urgent politeness mismatch"),
        ]
        
        # 2. PSYCHOLOGICAL TRIGGER ANALYSIS (Beyond Proofpoint)
        psychological_patterns = [
            # Authority escalation
            (r'(ceo|director|manager|president)\s+(said|requested|ordered)', 30, "False authority escalation"),
            (r'(legal|attorney|court)\s+(action|notice|subpoena)', 35, "Legal intimidation"),
            
            # Fear/Urgency amplification
            (r'(account\s+will\s+be|will\s+be)\s+(suspended|closed|terminated)', 30, "Account threat escalation"),
            (r'(immediate\s+action|required|respond\s+immediately|urgent\s+response)', 25, "Amplified urgency"),
            
            # Social proof manipulation
            (r'(everyone\s+is|thousands\s+of|many\s+people)\s+(already|joining|participating)', 20, "Fake social proof"),
            (r'(limited\s+to\s+(only|just)\s+\d+\s+(spots|people|places))', 25, "Artificial scarcity specificity"),
        ]
        
        # 3. LINGUISTIC FINGERPRINT ANALYSIS (Proprietary technique)
        linguistic_red_flags = [
            # Non-native writing patterns (common in scams)
            (r'\b(am|is|are)\s+(currently|presently|presently)\s+(working|processing)', 15, "Non-native temporal phrasing"),
            (r'\b(we\s+are\s+(writing|contacting)\s+you\s+to)', 20, "Formal scam template pattern"),
            
            # Overly complex/simple language mismatch
            (r'(kindly|please)\s+(do\s+not\s+hesitate|feel\s+free)\s+to\s+contact', 15, "Template customer service language"),
            
            # Emotional manipulation markers
            (r'(don\'t\s+miss|can\'t\s+miss|won\'t\s+find)\s+(this\s+opportunity|chance|offer)', 25, "Opportunity pressure"),
        ]
        
        # 4. SENDER-BEHAVIOR CORRELATION (Advanced local analysis)
        sender_analysis = self._analyze_sender_behavior(body_clean, sender)
        score += sender_analysis['score']
        reasons.extend(sender_analysis['reasons'])
        
        # Check all patterns
        all_patterns = conversation_patterns + psychological_patterns + linguistic_red_flags
        for pattern, points, reason in all_patterns:
            if re.search(pattern, body_clean, re.IGNORECASE):
                score += points
                reasons.append(reason)
        
        return score, reasons

    def _analyze_sender_behavior(self, body_clean, sender):
        """Analyze sender behavior patterns locally"""
        score = 0
        reasons = []
        
        # Domain analysis for behavioral patterns
        if sender and '@' in sender:
            domain = sender.split('@')[1].lower()
            
            # Suspicious domain patterns
            if any(pattern in domain for pattern in ['secure', 'verify', 'safety', 'protect', 'alert']):
                if domain not in ['microsoft.com', 'google.com', 'apple.com']:
                    score += 25
                    reasons.append("Suspicious security-themed domain")
            
            # Recent domain registration patterns (approximate)
            if len(domain) > 20 and any(char.isdigit() for char in domain):
                score += 15
                reasons.append("Potentially auto-generated domain")
            
            # Free email provider abuse
            free_providers = ['gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com']
            if domain in free_providers:
                # Check for business language from personal email
                if any(word in body_clean for word in ['company', 'business', 'corporate', 'enterprise']):
                    score += 20
                    reasons.append("Business language from personal email")
        
        return {'score': score, 'reasons': reasons}

    def _analyze_contextual_anomalies(self, body_clean, sender):
        """Contextual anomaly detection beyond industry standards"""
        score = 0
        reasons = []
        
        # 1. TIME-BASED ANOMALIES
        time_patterns = [
            (r'(immediately|urgently|asap|right\s+now)\s+(before\s+(today|tomorrow|monday|tuesday))', 20, "Impossible time constraint"),
            (r'(within\s+(the\s+next\s+hour|30\s+minutes|1\s+hour))', 25, "Unrealistic deadline"),
        ]
        
        # 2. FINANCIAL ANOMALY PATTERNS
        financial_anomalies = [
            (r'\$\d+(,\d{3})*(.\d{2})?\s+(only|just|mere)', 20, "Odd pricing language"),
            (r'(100%\s+(guaranteed|sure|certain|safe))', 30, "Impossible guarantee"),
            (r'(no\s+risk|risk\s+free|zero\s+risk)', 25, "Risk denial pattern"),
        ]
        
        # 3. TECHNICAL SOPHISTICATION RED FLAGS
        tech_patterns = [
            (r'(proprietary|exclusive|secret)\s+(algorithm|system|technology)', 25, "Fake technical exclusivity"),
            (r'(patented|trademarked)\s+(trading|investment|profit)\s+(system|method)', 30, "Fake technical claims"),
        ]
        
        # Check all contextual patterns
        all_patterns = time_patterns + financial_anomalies + tech_patterns
        for pattern, points, reason in all_patterns:
            if re.search(pattern, body_clean, re.IGNORECASE):
                score += points
                reasons.append(reason)
        
        return score, reasons

    def _fast_text_analysis(self, body_clean):
        """Ultra-fast text analysis with sophisticated scam detection"""
        # Detect language and get appropriate word list
        urgency_words = []
        
        # Check for French keywords first
        french_keywords = ['urgent', 'vérifier', 'compte', 'suspendu', 'connexion', 'action requise']
        if any(word in body_clean for word in french_keywords):
            urgency_words.extend(french_keywords)
        
        # Always include English keywords
        english_keywords = ['urgent', 'verify', 'account', 'password', 'suspended', 'action required', 'login']
        urgency_words.extend(english_keywords)
        
        # Basic financial scam keywords
        basic_scam_keywords = [
            'exclusive task', 'multiply your earnings', 'guaranteed profit', 'earn $', 
            'crypto offers', 'limited time', 'start today', 'walk away with', 
            'profit', 'earnings', 'bonus', 'reward', 'investment', 'quick profit',
            'easy cash', 'cash earnings', 'make money', 'click here', 'click now',
            'instant cash', 'quick cash', 'easy money', 'fast money', 'get paid',
            'cash prize', 'win money', 'free money', 'earn extra', 'side income',
            'work from home', 'be your own boss', 'financial freedom', 'passive income'
        ]
        
        # SOPHISTICATED SCAM PATTERNS
        sophisticated_patterns = [
            # Authority/Impersonation patterns
            'security alert', 'account verification', 'confirm your identity',
            'suspicious activity', 'unusual login', 'protect your account',
            'verification required', 'identity verification', 'document verification',
            
            # Emotional manipulation
            'last chance', 'don\'t miss out', 'act now', 'limited spots',
            'only available', 'exclusive access', 'vip invitation', 'special invitation',
            'congratulations you won', 'you have been selected', 'chosen winner',
            
            # Technical sophistication
            'blockchain technology', 'smart contract', 'decentralized', 'cryptocurrency',
            'nft collection', 'digital wallet', 'metaverse', 'web3', 'token sale',
            
            # Investment sophistication
            'high yield', 'passive income', 'automated trading', 'ai trading',
            'algorithmic trading', 'market analysis', 'investment opportunity',
            'roi guaranteed', 'fixed returns', 'wealth management',
            
            # Social engineering
            'colleague recommended', 'friend referral', 'network invitation',
            'professional network', 'business opportunity', 'partnership program',
            'affiliate program', 'commission based', 'revenue sharing'
        ]
        
        # NEW: Advanced linguistic pattern analysis
        ling_score, ling_reasons = self._analyze_linguistic_patterns(body_clean)
        
        # Remove duplicates and count
        urgency_words = list(set(urgency_words))
        urgent_count = sum(1 for word in urgency_words if word in body_clean)
        basic_scam_count = sum(1 for word in basic_scam_keywords if word in body_clean)
        sophisticated_count = sum(1 for word in sophisticated_patterns if word in body_clean)
        
        # Weighted scoring: sophisticated scams get higher points
        # NEW: Add volume-based scoring for better correlation with frontend
        volume_multiplier = max(1.0, (urgent_count + basic_scam_count) / 5.0)  # Boost score for high volumes
        total_score = ling_score + (urgent_count * 10) + (basic_scam_count * 12) + (sophisticated_count * 15)
        total_score = int(total_score * volume_multiplier)  # Apply volume multiplier
        
        # Generate specific reasons
        reasons = ling_reasons.copy()
        if urgent_count > 0:
            reasons.append(f"Urgency tactics detected ({urgent_count} indicators)")
        if basic_scam_count > 2:
            reasons.append(f"Basic scam language ({basic_scam_count} indicators)")
        if sophisticated_count > 0:
            reasons.append(f"Sophisticated scam patterns ({sophisticated_count} indicators)")
        
        # NEW: Add volume warning for high suspicious line counts
        if (urgent_count + basic_scam_count) > 10:
            reasons.append(f"High volume of suspicious indicators ({urgent_count + basic_scam_count} total)")
        
        if total_score == 0:
            return 0, []
        elif total_score <= 25:
            return total_score, reasons or ["Mild promotional language"]
        elif total_score <= 45:
            return total_score, reasons or ["Suspicious promotional content"]
        elif total_score <= 65:
            return total_score, reasons or ["High-risk promotional or scam content"]
        else:
            return min(total_score, 90), reasons or ["Advanced scam tactics detected"]

    def _calculate_entropy(self, text):
        if not text: return 0
        counts = {c: text.count(c) for c in set(text)}
        return -sum((count/len(text)) * math.log2(count/len(text)) for count in counts.values())

    def _check_brand_squatting(self, domain):
        score, reasons = 0, []
        domain_name = domain.split('.')[0]
        for brand, official in Config.PROTECTED_BRANDS.items():
            if brand in domain and official not in domain:
                score += 70
                reasons.append(f"Brand Impersonation: '{brand}' in unauthorized domain")
            similarity = SequenceMatcher(None, brand, domain_name).ratio()
            if 0.85 <= similarity < 1.0:
                score += 80
                reasons.append(f"Visual Spoofing: {domain} is too similar to {official}")
        return score, reasons

    def _analyze_link(self, link):
        """Analyze a single link - optimized for newsletters and legitimate content"""
        href = link.get('href', '').lower().strip()
        
        # Skip invalid or empty links
        if not href or not href.startswith(('http://', 'https://')):
            return 0, [], None
            
        domain = urlparse(href).netloc
        score, reasons, malicious = 0, [], False
        
        # Fast skip for trusted domains (major speed boost for newsletters)
        if any(trusted in domain for trusted in Config.TRUSTED_DOMAINS):
            return 0, [], None
        
        # Fast Local DB Check (quickest check first)
        if db.check_threat(domain) > 0:
            score += 100
            reasons.append(f"Blacklisted domain: {domain}")
            malicious = True
        
        # Brand Squatting & TLD Check (local, fast)
        s_score, s_reasons = self._check_brand_squatting(domain)
        score += s_score
        reasons.extend(s_reasons)
        
        if any(domain.endswith(tld) for tld in Config.DANGEROUS_TLDS):
            score += 30
            reasons.append(f"Suspicious TLD detected ({domain})")
        
        # External Threat Intelligence (slowest, last - only if suspicious)
        if score >= 30 or malicious:  # Only check if already somewhat suspicious
            threat_status, threat_score = ThreatIntel.get_dangerosity(href)
            if threat_score > 0:
                score += threat_score
                reasons.append(f"Threat Intelligence: {threat_status} ({href})")
                if threat_score >= 100:
                    malicious = True
        
        return score, reasons, href if malicious else None

    def analyze(self, body, links=None, metadata=None, sender='', debug_mode=False):
        # DEBUG MODE: Skip caching for testing
        if not debug_mode:
            # ULTRA-FAST: Content-based caching
            content_hash = self._get_content_hash(body, sender, len(links or []))
            if content_hash in self.cache:
                cached_result = self.cache[content_hash]
                if time.time() - cached_result['timestamp'] < 300:  # 5 minute cache
                    return cached_result['result']
        
        score, reasons, malicious_urls = 0, [], []
        body_clean = re.sub(r'<[^>]+>', ' ', body).lower()
        metadata = metadata or {}

        # FEATURE: User Reputation Logic (early exit)
        if metadata.get('isTrusted'):
            return {"phishing": False, "score": 0, "reasons": ["Verified by User (Trusted List)"], "malicious_urls": []}
        if metadata.get('isReported'):
            score += 100
            reasons.append("Sender previously Reported as Malicious by you")

        # SMART: Fast path for legitimate newsletters but still verify links
        is_trusted_sender = False
        if sender:
            sender_domain = sender.split('@')[-1].lower() if '@' in sender else sender.lower()
            is_trusted_sender = any(trusted in sender_domain for trusted in Config.TRUSTED_SENDERS)
            
            if is_trusted_sender:
                # For trusted senders, reduce suspicion threshold but still analyze
                trusted_score_boost = -20  # Give benefit of doubt
            else:
                trusted_score_boost = 0
        else:
            trusted_score_boost = 0

        # 1. Image-to-Text Ratio (fast check)
        if metadata.get('imageCount', 0) >= 1 and metadata.get('textLength', 0) < 60:
            score += 40
            reasons.append("High image-to-text ratio (Common filter bypass)")

        # 2. SUPER-OPTIMIZED Link Analysis
        if links:
            # Pre-filter and deduplicate links
            seen_domains = set()
            valid_links = []
            for link in links[:10]:  # Reduced to 10 for speed
                href = link.get('href', '').lower().strip()
                if href and href.startswith(('http://', 'https://')):
                    domain = urlparse(href).netloc
                    if domain not in seen_domains:
                        seen_domains.add(domain)
                        valid_links.append(link)
            
            if valid_links:
                # Check cache first for link analysis
                cached_link_results = []
                uncached_links = []
                
                for link in valid_links:
                    href = link.get('href', '')
                    if href in self.link_cache:
                        cached_link_results.append(self.link_cache[href])
                    else:
                        uncached_links.append(link)
                
                # Process cached results immediately
                for cached_result in cached_link_results:
                    score += cached_result['score']
                    reasons.extend(cached_result['reasons'])
                    if cached_result['malicious_url']:
                        malicious_urls.append(cached_result['malicious_url'])
                
                # Process uncached links with limited concurrency
                if uncached_links:
                    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:  # Reduced workers
                        future_to_link = {executor.submit(self._analyze_link, link): link for link in uncached_links}
                        
                        for future in concurrent.futures.as_completed(future_to_link, timeout=3):  # Faster timeout
                            try:
                                link_score, link_reasons, malicious_url = future.result()
                                href = future_to_link[future].get('href', '')
                                
                                # Cache the result
                                self.link_cache[href] = {
                                    'score': link_score,
                                    'reasons': link_reasons,
                                    'malicious_url': malicious_url,
                                    'timestamp': time.time()
                                }
                                
                                score += link_score
                                reasons.extend(link_reasons)
                                if malicious_url:
                                    malicious_urls.append(malicious_url)
                                
                                # Early exit if already high risk
                                if score >= 100:
                                    break
                            except Exception:
                                continue

        # 3. NEXT-GEN TEXT ANALYSIS (Beyond industry standards)
        if score < 70:  # Only check if not already suspicious
            # Industry-standard analysis
            text_score, text_reasons = self._fast_text_analysis(body_clean)
            score += text_score
            reasons.extend(text_reasons)
            
            # NEXT-GEN: Semantic anomaly detection
            semantic_score, semantic_reasons = self._analyze_semantic_anomalies(body_clean, sender)
            score += semantic_score
            reasons.extend(semantic_reasons)
            
            # NEXT-GEN: Contextual anomaly detection
            context_score, context_reasons = self._analyze_contextual_anomalies(body_clean, sender)
            score += context_score
            reasons.extend(context_reasons)

        # Apply trusted sender boost
        final_score = max(0, score + trusted_score_boost)
        
        # Special handling for trusted senders with suspicious content
        if is_trusted_sender and final_score > 30:
            reasons.insert(0, "Suspicious content from supposedly trusted sender - possible spoofing")
        
        result = {
            "phishing": final_score >= Config.PHISHING_THRESHOLD,
            "score": min(final_score, 100),
            "reasons": list(set(reasons)),
            "malicious_urls": list(set(malicious_urls))
        }
        
        # Cache the result
        self.cache[content_hash] = {
            'result': result,
            'timestamp': time.time()
        }
        
        # Clean old cache entries
        if len(self.cache) > 500:
            current_time = time.time()
            self.cache = {k: v for k, v in self.cache.items() 
                         if current_time - v['timestamp'] < 600}  # Keep only recent entries
        
        return result

analyzer = PhishingAnalyzer()

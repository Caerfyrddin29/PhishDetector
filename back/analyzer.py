import re
import math
from urllib.parse import urlparse
from difflib import SequenceMatcher
import unicodedata

from config import Config
from db_manager import db
from threat_intel import ThreatIntel

class PhishingAnalyzer:
    def _calculate_entropy(self, text):
        if not text: return 0
        counts = {c: text.count(c) for c in set(text)}
        return -sum((count/len(text)) * math.log2(count/len(text)) for count in counts.values())

    def _check_typosquatting(self, domain):
        score, reasons = 0, []
        domain_name = domain.split('.')[0]
        for brand, official in Config.PROTECTED_BRANDS.items():
            if brand in domain and official not in domain:
                score += 70
                reasons.append(f"Brand Impersonation: '{brand}' in unauthorized domain")
            
            similarity = SequenceMatcher(None, brand, domain_name).ratio()
            if 0.85 <= similarity < 1.0:
                score += 85
                reasons.append(f"Visual Spoofing: Domain is suspiciously similar to {official}")
        return score, reasons

    def _detect_language(self, text):
        """Detect the primary language of the text"""
        try:
            # Normalize text for language detection
            clean_text = re.sub(r'[\u0000-\u001F\u007F-\u009F]', '', text)
            
            # Simple language detection based on character patterns
            if re.search(r'[\u4e00-\u9fff]', clean_text):  # Chinese
                return 'zh'
            elif re.search(r'[\u0600-\u06FF]', clean_text):  # Arabic
                return 'ar'
            elif re.search(r'[\u0400-\u04FF]', clean_text):  # Cyrillic
                return 'ru'
            elif re.search(r'[\u0590-\u05FF]', clean_text):  # Hebrew
                return 'he'
            elif re.search(r'[\u0900-\u097F]', clean_text):  # Hindi
                return 'hi'
            elif re.search(r'[\u0E00-\u0E7F]', clean_text):  # Thai
                return 'th'
            # French detection - look for French-specific characters and patterns
            elif re.search(r'[àâäçéèêëïîôöùûüÿ]', clean_text):  # French accents
                return 'fr'
            else:
                return 'en'  # Default to English
        except:
            return 'en'

    def _get_multilingual_keywords(self, language):
        """Get phishing keywords for different languages"""
        keywords = {
            'en': {
                'urgency': ['urgent', 'verify', 'suspended', 'action required', 'immediate', 'critical', 'alert', 'warning'],
                'financial': ['invoice', 'refund', 'payment', 'transaction', 'credits', 'billing', 'account'],
                'security': ['unauthorized', 'detected', 'security alert', 'compromised', 'breach', 'suspicious']
            },
            'zh': {
                'urgency': ['紧急', '验证', '暂停', '立即', '重要', '警告'],
                'financial': ['发票', '退款', '付款', '交易', '账户', '账单'],
                'security': ['未经授权', '检测到', '安全警报', '泄露', '可疑']
            },
            'ar': {
                'urgency': ['عاجل', 'تحقق', 'معلق', 'فوري', 'حرج', 'إنذار'],
                'financial': ['فاتورة', 'استرداد', 'دفع', 'معاملة', 'حساب'],
                'security': ['غير مصرح', 'تم الكشف', 'تنبيه أمني', 'اختراق', 'مشبوه']
            },
            'ru': {
                'urgency': ['срочно', 'проверить', 'приостановлен', 'немедленно', 'критический', 'предупреждение'],
                'financial': ['счет', 'возврат', 'оплата', 'транзакция', 'аккаунт', 'выставление счета'],
                'security': ['несанкционированный', 'обнаружено', 'предупреждение безопасности', 'скомпрометирован', 'подозрительный']
            },
            'es': {
                'urgency': ['urgente', 'verificar', 'suspendido', 'inmediato', 'crítico', 'alerta'],
                'financial': ['factura', 'reembolso', 'pago', 'transacción', 'créditos', 'cuenta'],
                'security': ['no autorizado', 'detectado', 'alerta de seguridad', 'comprometido', 'sospechoso']
            },
            'fr': {
                'urgency': ['urgent', 'vérifier', 'suspendu', 'action requise', 'immédiat', 'critique', 'alerte', 'attention'],
                'financial': ['facture', 'remboursement', 'paiement', 'transaction', 'crédit', 'facturation', 'compte'],
                'security': ['non autorisé', 'détecté', 'alerte de sécurité', 'compromis', 'suspect', 'piratage']
            }
        }
        return keywords.get(language, keywords['en'])

    def _check_obfuscation(self, text):
        """Check for text obfuscation techniques"""
        score, reasons = 0, []
        
        # Check for excessive special characters
        special_char_ratio = len(re.findall(r'[^a-zA-Z0-9\s]', text)) / max(len(text), 1)
        if special_char_ratio > 0.3:
            score += 25
            reasons.append("High ratio of special characters (obfuscation technique)")
        
        # Check for URL encoding
        if re.search(r'%[0-9A-Fa-f]{2}', text):
            score += 30
            reasons.append("URL encoding detected (possible obfuscation)")
        
        # Check for excessive whitespace
        if re.search(r'\s{5,}', text):
            score += 15
            reasons.append("Excessive whitespace (obfuscation technique)")
        
        # Check for character substitution (leetspeak)
        leet_patterns = [('4', 'a'), ('3', 'e'), ('1', 'i'), ('0', 'o'), ('7', 't'), ('5', 's')]
        leet_count = sum(text.lower().count(pattern) for pattern, _ in leet_patterns)
        if leet_count > 2:
            score += 20
            reasons.append("Leetspeak detected (character substitution)")
        
        return score, reasons

    def _check_suspicious_patterns(self, text, links):
        """Check for suspicious patterns in email content"""
        score, reasons = 0, []
        
        # Check for shortened URLs - but be less aggressive
        shorteners = ['bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd']
        shortener_count = 0
        for link in links:
            href = link.get('href', '').lower()
            if any(shortener in href for shortener in shorteners):
                shortener_count += 1
        
        # Only penalize if multiple shortened URLs
        if shortener_count >= 2:
            score += 30
            reasons.append(f"Multiple URL shorteners detected ({shortener_count})")
        elif shortener_count == 1:
            score += 10  # Minor penalty for single shortener
            reasons.append("URL shortener detected")
        
        # Check for IP address URLs - more specific pattern
        ip_pattern = r'https?://\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}($|/)'
        if re.search(ip_pattern, str(links)):
            score += 50
            reasons.append("Direct IP address URL detected")
        
        # Check for non-standard ports - only high ports
        for link in links:
            href = link.get('href', '')
            if re.search(r':(8080|3000|8000|9000|4444|5555)\b', href):
                score += 25
                reasons.append(f"Suspicious port in URL: {href}")
        
        # Check for excessive urgency - higher threshold
        urgency_indicators = ['!!', '!!!', 'urgent', 'immediate', 'asap', 'now']
        urgency_count = sum(text.lower().count(indicator) for indicator in urgency_indicators)
        if urgency_count >= 4:  # Increased from 3
            score += 25  # Reduced from 35
            reasons.append("Excessive urgency indicators detected")
        
        return score, reasons

    def analyze(self, body, links=None, metadata=None):
        score, reasons, malicious_urls = 0, [], []
        body_clean = re.sub(r'<[^>]+>', ' ', body).lower()
        metadata = metadata or {}

        # Detect language for multilingual analysis
        language = self._detect_language(body)
        
        # 1. Structural Checks (Invisible link/Image-only)
        if metadata.get('hasHiddenLinks'):
            score += 100
            reasons.append("Invisible link overlay detected (High-Certainty)")

        if metadata.get('imageCount', 0) > 0 and metadata.get('textLength', 0) < 50:
            score += 50
            reasons.append("Image-heavy email with low text (Phishing Bypass method)")

        # 2. Enhanced Pattern Analysis
        obf_score, obf_reasons = self._check_obfuscation(body_clean)
        score += obf_score
        reasons.extend(obf_reasons)
        
        pattern_score, pattern_reasons = self._check_suspicious_patterns(body_clean, links)
        score += pattern_score
        reasons.extend(pattern_reasons)

        # 3. Link Analysis (Cached & Multi-layered)
        for link in links or []:
            href = link.get('href', '').lower()
            text = link.get('text', '').lower()
            domain = urlparse(href).netloc

            # A. Check Local Database (Instant)
            threat_level = db.check_threat(domain)
            if threat_level >= 70:
                score += 100
                reasons.append(f"Blacklisted Domain: {domain}")
                malicious_urls.append(href)
                continue

            # B. Check Deceptive Text (href != display text)
            if ('.com' in text or 'www' in text) and domain and domain not in text:
                score += 100
                reasons.append(f"Masked URL: Display text is '{text}' but links to '{domain}'")
                malicious_urls.append(href)

            # C. Typosquatting & Entropy
            t_score, t_reasons = self._check_typosquatting(domain)
            score += t_score
            reasons.extend(t_reasons)
            
            if self._calculate_entropy(domain) > 4.2:
                score += 30
                reasons.append(f"Suspicious high-entropy domain: {domain}")

        # 4. Multilingual Linguistic Check
        keywords = self._get_multilingual_keywords(language)
        hits = []
        for category, words in keywords.items():
            for word in words:
                if word in body_clean:
                    hits.append(f"{category}:{word}")
        
        if hits:
            # More conservative scoring for linguistic indicators
            unique_categories = len(set(hit.split(':')[0] for hit in hits))
            word_count = len(hits)
            
            # Only score if multiple categories OR multiple words
            if unique_categories >= 2 or word_count >= 3:
                linguistic_score = min(unique_categories * 15 + word_count * 5, 50)  # Reduced scoring
                score += linguistic_score
                
                # Show detected keywords in results
                detected_keywords = [hit.split(':')[1] for hit in hits[:5]]  # Show first 5
                reasons.append(f"Suspicious keywords ({language}): {', '.join(detected_keywords)}")

        # 5. Additional Advanced Checks
        # Check for sender impersonation - be more specific
        if metadata.get('sender'):
            sender = metadata.get('sender', '').lower()
            sender_domain = sender.split('@')[-1] if '@' in sender else ''
            
            # Only flag if sender domain is suspicious
            for brand, official in Config.PROTECTED_BRANDS.items():
                if brand in sender_domain and sender_domain != official:
                    # Check if it's a known suspicious pattern
                    suspicious_patterns = [f'{brand}-security', f'{brand}-verify', f'{brand}-login', f'secure-{brand}']
                    if any(pattern in sender_domain for pattern in suspicious_patterns):
                        score += 30  # Reduced from 40
                        reasons.append(f"Suspicious sender domain: {sender_domain}")
                        break
        
        # Check sender IP if available
        if metadata.get('senderIP'):
            sender_ip = metadata.get('senderIP')
            # Check if it's a private IP or suspicious
            if sender_ip.startswith('192.168.') or sender_ip.startswith('10.') or sender_ip.startswith('172.16.'):
                score += 20
                reasons.append("Sender from private network range")
        
        # Check for attachment threats - only if suspicious
        if metadata.get('hasAttachments') and metadata.get('attachmentCount', 0) > 3:
            score += 15  # Reduced from 20
            reasons.append("Multiple attachments detected")
        
        # Check for encoding anomalies - be less sensitive
        try:
            body.encode('ascii')
        except UnicodeEncodeError:
            # Only penalize if excessive non-ASCII
            non_ascii_ratio = sum(1 for c in body if ord(c) > 127) / len(body)
            if non_ascii_ratio > 0.3:  # Only if >30% non-ASCII
                score += 10  # Reduced from 15
                reasons.append("High non-ASCII character content")

        return {
            "phishing": score >= Config.PHISHING_THRESHOLD,
            "score": min(score, 100),
            "reasons": list(set(reasons)),
            "malicious_urls": list(set(malicious_urls)),
            "language": language,
            "analysis_version": "2.0"
        }

# Initialize analyzer
analyzer = PhishingAnalyzer()

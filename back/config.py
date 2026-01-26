import os
import time

class Config:
    HOST = '127.0.0.1'
    PORT = 5001  # Synchronized with extension
    PHISHING_THRESHOLD = 50
    DB_PATH = 'urls.db'
    GITHUB_DB_URL = 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt'
    
    # OFFICIAL MAPPING: Brand -> Official Domain
    PROTECTED_BRANDS = {
        'paypal': 'paypal.com',
        'google': 'google.com',
        'microsoft': 'microsoft.com',
        'amazon': 'amazon.com',
        'netflix': 'netflix.com',
        'apple': 'apple.com',
        'binance': 'binance.com',
        'metamask': 'metamask.io'
    }

    # Trusted domains (skip analysis for speed)
    TRUSTED_DOMAINS = {
        'quora.com', 'facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com',
        'youtube.com', 'wikipedia.org', 'reddit.com', 'medium.com', 'github.com',
        'stackoverflow.com', 'apple.com', 'google.com', 'microsoft.com', 'amazon.com'
    }

    # Trusted sender domains (newsletters, legitimate services)
    TRUSTED_SENDERS = {
        'quora.com', 'noreply.quora.com', 'mail.quora.com',
        'linkedin.com', 'notifications.linkedin.com',
        'facebook.com', 'facebookmail.com',
        'twitter.com', 'x.com',
        'instagram.com', 'mail.instagram.com',
        'medium.com', 'notifications.medium.com',
        'github.com', 'noreply.github.com'
    }

    # Suspicious Top-Level Domains (New Feature)
    DANGEROUS_TLDS = ['.zip', '.mov', '.top', '.work', '.click', '.xyz']

    LEXICON = {
        'EN': ['urgent', 'verify', 'account', 'password', 'suspended', 'action required', 'login'],
        'FR': ['urgent', 'vérifier', 'compte', 'suspendu', 'connexion', 'action requise']
    }

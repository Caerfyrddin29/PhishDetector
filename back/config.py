# Configuration file for my phishing detector
# All the settings and stuff are in here
import os
import time

class Config:
    # Server settings
    HOST = '127.0.0.1'  # Localhost
    PORT = 5001  # This port matches the browser extension
    
    # Phishing detection threshold
    # If score is above this, it's probably phishing
    PHISHING_THRESHOLD = 50
    
    # Database file path
    DB_PATH = 'urls.db'
    
    # URL to get the latest list of bad websites
    GITHUB_DB_URL = 'https://raw.githubusercontent.com/mitchellkrogza/Phishing.Database/master/phishing-domains-ACTIVE.txt'
    
    # Big companies that scammers like to impersonate
    # Format: brand name -> real website
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

    # Websites we know are safe (skip them to make it faster)
    TRUSTED_DOMAINS = {
        'quora.com', 'facebook.com', 'twitter.com', 'linkedin.com', 'instagram.com',
        'youtube.com', 'wikipedia.org', 'reddit.com', 'medium.com', 'github.com',
        'stackoverflow.com', 'apple.com', 'google.com', 'microsoft.com', 'amazon.com'
    }

    # Email addresses that send legitimate stuff
    TRUSTED_SENDERS = {
        'quora.com', 'noreply.quora.com', 'mail.quora.com',
        'linkedin.com', 'notifications.linkedin.com',
        'facebook.com', 'facebookmail.com',
        'twitter.com', 'x.com',
        'instagram.com', 'mail.instagram.com',
        'medium.com', 'notifications.medium.com',
        'github.com', 'noreply.github.com'
    }

    # Suspicious website endings that scammers use a lot
    DANGEROUS_TLDS = ['.zip', '.mov', '.top', '.work', '.click', '.xyz']

    # Keywords for different languages (I support English and French!)
    LEXICON = {
        'EN': ['urgent', 'verify', 'account', 'password', 'suspended', 'action required', 'login'],
        'FR': ['urgent', 'vérifier', 'compte', 'suspendu', 'connexion', 'action requise']
    }

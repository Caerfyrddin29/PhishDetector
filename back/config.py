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
        'metamask': 'metamask.io',
        # French brands
        'societe generale': 'socgen.com',
        'bnp paribas': 'bnpparibas.fr',
        'credit agricole': 'credit-agricole.fr',
        'lcl': 'lcl.fr',
        'caisse depot': 'caissedepot.fr',
        'banque postale': 'banquepostale.fr',
        'orange': 'orange.fr',
        'sfr': 'sfr.fr',
        'bouygues': 'bouygues.fr',
        'free': 'free.fr',
        'la poste': 'laposte.fr',
        'sncf': 'sncf.fr',
        'ratp': 'ratp.fr',
        'edf': 'edf.fr',
        'engie': 'engie.fr',
        'total': 'total.com',
        'carrefour': 'carrefour.fr',
        'auchan': 'auchan.fr',
        'leclerc': 'e.leclerc',
        'fnac': 'fnac.com',
        'decathlon': 'decathlon.fr',
        'lidl': 'lidl.fr',
        'intermarché': 'intermarche.com'
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
        'EN': {
            'urgency': ['urgent', 'immediately', 'asap', 'right away', 'now', 'today only', 'limited time', 'expires soon', 'hurry', 'act fast', 'don\'t wait', 'last chance', 'final notice', 'immediate action required'],
            'account_security': ['verify', 'account', 'password', 'suspended', 'action required', 'login', 'security', 'confirm', 'authenticate', 'locked', 'blocked', 'deactivated', 'closure', 'terminate'],
            'scam_indicators': ['exclusive task', 'multiply your earnings', 'guaranteed profit', 'earn $', 'cash prize', 'winner', 'congratulations', 'free money', 'quick cash', 'easy money', 'work from home', 'be your own boss', 'financial freedom', 'investment opportunity', 'risk free', 'no experience needed'],
            'manipulation': ['congratulations', 'winner', 'selected', 'chosen', 'exclusive', 'limited offer', 'special promotion', 'vip treatment', 'priority access', 'secret method', 'insider information'],
            'threats': ['suspended', 'closed', 'terminated', 'deactivated', 'blocked', 'locked', 'legal action', 'lawsuit', 'arrest', 'prosecution', 'account closure', 'service termination'],
            'pressure': ['immediately', 'within 24 hours', 'today', 'right now', 'don\'t delay', 'act now', 'urgent response needed', 'time sensitive', 'expiring soon']
        },
        'FR': {
            'urgency': ['urgent', 'immédiatement', 'dès maintenant', 'tout de suite', 'maintenant', 'aujourd\'hui seulement', 'temps limité', 'expire bientôt', 'dépêchez-vous', 'agissez vite', 'n\'attendez pas', 'dernière chance', 'avis final', 'action immédiate requise', 'sans délai', 's\'il vous plaît agir'],
            'account_security': ['vérifier', 'compte', 'mot de passe', 'suspendu', 'action requise', 'connexion', 'sécurité', 'confirmer', 'authentifier', 'bloqué', 'verrouillé', 'désactivé', 'fermeture', 'résilier', 'clôturer', 'sécurisation'],
            'scam_indicators': ['tâche exclusive', 'multipliez vos gains', 'profit garanti', 'gagnez $', 'prix en argent', 'gagnant', 'félicitations', 'argent gratuit', 'argent rapide', 'argent facile', 'travail à domicile', 'soyez votre propre patron', 'liberté financière', 'opportunité d\'investissement', 'sans risque', 'aucune expérience requise'],
            'manipulation': ['félicitations', 'gagnant', 'sélectionné', 'choisi', 'exclusif', 'offre limitée', 'promotion spéciale', 'traitement vip', 'accès prioritaire', 'méthode secrète', 'information interne', 'opportunité unique'],
            'threats': ['suspendu', 'fermé', 'résilié', 'désactivé', 'bloqué', 'verrouillé', 'action en justice', 'poursuite judiciaire', 'arrestation', 'poursuite', 'fermeture de compte', 'résiliation de service'],
            'pressure': ['immédiatement', 'dans 24 heures', 'aujourd\'hui', 'maintenant', 'ne retardez pas', 'agissez maintenant', 'réponse urgente nécessaire', 'sensible au temps', 'expire bientôt', 'sans délai']
        }
    }

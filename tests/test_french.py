#!/usr/bin/env python3
import sys
sys.path.append('back')
from analyzer import analyzer

# Test French content detection
result = analyzer.analyze(
    body='Saisissez les offres dès maintenant. Votre compte est suspendu. Action requise!',
    sender='test@french-scam.fr',
    metadata={'imageCount': 0, 'textLength': 80}
)

print(f'French detection test:')
print(f'Score: {result["score"]}')
print(f'Phishing: {result["phishing"]}')
print(f'Reasons: {result["reasons"]}')

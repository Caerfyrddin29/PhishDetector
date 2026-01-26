#!/usr/bin/env python3
import sys
sys.path.append('back')
from analyzer import analyzer

# Test image-heavy email with minimal text
result = analyzer.analyze(
    body='Click here now',
    links=[],
    metadata={'imageCount': 2, 'textLength': 15}
)

print(f'Image-heavy phishing detection: {result["phishing"]}')
print(f'Score: {result["score"]}')
print(f'Reasons: {result["reasons"]}')

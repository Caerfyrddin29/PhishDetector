#!/usr/bin/env python3
import sys
sys.path.append('back')
from analyzer import analyzer

# Test with mixed content (legitimate + scam)
mixed_content = """
Hello John,

This is your monthly newsletter from TechCorp with updates about our latest products.

We're excited to announce our new feature releases and upcoming webinars.

SPECIAL OFFER: Get easy cash today! Click here to start earning $500 per day. 
This is your chance to make money fast. Get paid instantly for simple tasks.
Limited time offer - don't miss out on this opportunity.

Thank you for being a valued customer.
Best regards,
TechCorp Team

---
Unsubscribe | Privacy Policy | Contact Us
"""

result1 = analyzer.analyze(
    body=mixed_content,
    sender='newsletter@techcorp.com',
    metadata={'imageCount': 0, 'textLength': len(mixed_content)}
)

print('Mixed Content Analysis:')
print(f'Total length: {len(mixed_content)} characters')
print(f'Score: {result1["score"]}')
print(f'Phishing: {result1["phishing"]}')
print(f'Reasons: {result1["reasons"]}')

# Test with just the scam part
scam_only = """
SPECIAL OFFER: Get easy cash today! Click here to start earning $500 per day. 
This is your chance to make money fast. Get paid instantly for simple tasks.
Limited time offer - don't miss out on this opportunity.
"""

result2 = analyzer.analyze(
    body=scam_only,
    sender='scam@easymoney.xyz',
    metadata={'imageCount': 0, 'textLength': len(scam_only)}
)

print('\nScam-Only Analysis:')
print(f'Scam length: {len(scam_only)} characters')
print(f'Score: {result2["score"]}')
print(f'Phishing: {result2["phishing"]}')
print(f'Reasons: {result2["reasons"]}')

print(f'\nDilution effect: {result1["score"]} vs {result2["score"]} ({((result1["score"]/result2["score"])*100):.1f}% of original score)')

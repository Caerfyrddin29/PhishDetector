#!/usr/bin/env python3
import sys
sys.path.append('back')
from analyzer import analyzer

# Test 1: Next-gen conversational anomaly detection
conversation_scam = """Dear friend,

I hope this email finds you well. I need your help urgently.
Trust me to handle this situation - only you can assist.

Respectfully, please respond immediately to this request.
We are currently working on processing your payment."""

result1 = analyzer.analyze(
    body=conversation_scam,
    sender='help@trust-me-secure.com',
    metadata={'imageCount': 0, 'textLength': len(conversation_scam)}
)

print('🧠 Next-Gen Conversational Anomaly Detection:')
print(f'Score: {result1["score"]}')
print(f'Phishing: {result1["is_phishing"]}')
print(f'Reasons: {result1["reasons"]}')

# Test 2: Advanced psychological manipulation
psychological_scam = """URGENT: The CEO said your account will be terminated immediately.

Immediate action required - respond immediately!
Everyone is joining this exclusive opportunity, limited to only 50 people.

100% guaranteed returns with zero risk. Don't miss this chance!"""

result2 = analyzer.analyze(
    body=psychological_scam,
    sender='ceo@corporate-action-alert.com',
    metadata={'imageCount': 0, 'textLength': len(psychological_scam)}
)

print('\n🎭 Advanced Psychological Manipulation:')
print(f'Score: {result2["score"]}')
print(f'Phishing: {result2["is_phishing"]}')
print(f'Reasons: {result2["reasons"]}')

# Test 3: Contextual anomaly with impossible constraints
contextual_scam = """Special offer: Get this amazing deal for only $99.99!

Act now before tomorrow - this offer expires within the next 30 minutes.
100% guaranteed or your money back - no risk whatsoever.

Our patented trading system uses proprietary algorithms for guaranteed profits."""

result3 = analyzer.analyze(
    body=contextual_scam,
    sender='offers@exclusive-deals-2024.xyz',
    metadata={'imageCount': 0, 'textLength': len(contextual_scam)}
)

print('\n⏰ Contextual Anomaly Detection:')
print(f'Score: {result3["score"]}')
print(f'Phishing: {result3["is_phishing"]}')
print(f'Reasons: {result3["reasons"]}')

# Test 4: Personal email with business language (sender behavior)
personal_business_scam = """Hello,

Our company needs your assistance with a business transaction.
Please contact us immediately regarding this corporate opportunity.

Thank you for your cooperation."""

result4 = analyzer.analyze(
    body=personal_business_scam,
    sender='business.deal12345@gmail.com',
    metadata={'imageCount': 0, 'textLength': len(personal_business_scam)}
)

print('\n📧 Sender Behavior Analysis:')
print(f'Score: {result4["score"]}')
print(f'Phishing: {result4["is_phishing"]}')
print(f'Reasons: {result4["reasons"]}')

print(f'\n🚀 Next-Gen Detection Summary:')
print(f'Conversational: {result1["score"]} pts')
print(f'Psychological: {result2["score"]} pts')
print(f'Contextual: {result3["score"]} pts')
print(f'Sender Behavior: {result4["score"]} pts')

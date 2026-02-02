#!/usr/bin/env python3
import sys
sys.path.append('back')
from analyzer import analyzer

# Test 1: Microsoft-style BEC detection
bec_scam = """Hi John,

URGENT: I need you to process a payment immediately for the client.
The CEO requested this wire transfer to be completed before end of day.

Can you quickly purchase gift cards for the vendor emergency?
This is confidential - only you can help with this situation.

Trust you to handle this request ASAP.
Thanks,
Director"""

result1 = analyzer.analyze(
    body=bec_scam,
    sender='director@company-corp.com',
    metadata={'imageCount': 0, 'textLength': len(bec_scam)}
)

print('💼 Microsoft-Style BEC Detection:')
print(f'Score: {result1["score"]}')
print(f'Phishing: {result1["is_phishing"]}')
print(f'Reasons: {result1["reasons"]}')

# Test 2: Proofpoint-style social engineering
social_scam = """Hello,

Customer emergency - we have a critical issue with your account.
Security verification required immediately to protect your data.

Please respond this weekend with the requested information.
This verification needs to be completed after hours.

Account update must be confirmed today."""

result2 = analyzer.analyze(
    body=social_scam,
    sender='security@verification-center.com',
    metadata={'imageCount': 0, 'textLength': len(social_scam)}
)

print('\n🎯 Proofpoint-Style Social Engineering:')
print(f'Score: {result2["score"]}')
print(f'Phishing: {result2["is_phishing"]}')
print(f'Reasons: {result2["reasons"]}')

# Test 3: Advanced crypto scam (industry best practices)
crypto_advanced = """Congratulations! You have been selected for exclusive access 
to our blockchain technology platform.

Limited spots available for our artificial intelligence trading system.
Cryptocurrency investment opportunity with guaranteed returns.

Our smart contract offers automated trading profits in the metaverse.
Special VIP invitation - only available to chosen winners."""

result3 = analyzer.analyze(
    body=crypto_advanced,
    sender='vip@crypto-investment.ai',
    metadata={'imageCount': 0, 'textLength': len(crypto_advanced)}
)

print('\n🚀 Advanced Crypto Scam Detection:')
print(f'Score: {result3["score"]}')
print(f'Phishing: {result3["is_phishing"]}')
print(f'Reasons: {result3["reasons"]}')

print(f'\n📊 Industry-Inspired Detection Summary:')
print(f'BEC Attack: {result1["score"]} pts')
print(f'Social Engineering: {result2["score"]} pts')
print(f'Advanced Crypto: {result3["score"]} pts')

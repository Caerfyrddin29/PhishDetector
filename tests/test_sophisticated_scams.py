#!/usr/bin/env python3
import sys
sys.path.append('back')
from analyzer import analyzer

# Test 1: Sophisticated impersonation scam
impersonation_scam = """Security Alert: Unusual login activity detected on your account.

Dear Valued Customer,

Our security system has detected suspicious activity on your account. 
For your protection, we require immediate identity verification.

Please confirm your identity within 24 hours to avoid account suspension.
Click here to verify your account now.

This is an automated security message from Microsoft Security Team."""

result1 = analyzer.analyze(
    body=impersonation_scam,
    sender='security@microsoft-verification.com',
    metadata={'imageCount': 0, 'textLength': len(impersonation_scam)}
)

print('🎭 Sophisticated Impersonation Scam:')
print(f'Score: {result1["score"]}')
print(f'Phishing: {result1["is_phishing"]}')
print(f'Reasons: {result1["reasons"]}')

# Test 2: Advanced crypto/investment scam
crypto_scam = """Exclusive Investment Opportunity: AI-Powered Trading Platform

Dear Investor,

Congratulations! You have been selected for exclusive access to our 
blockchain technology platform featuring automated trading algorithms.

Our smart contract system offers guaranteed ROI through algorithmic trading 
in the cryptocurrency market. Limited spots available for this VIP invitation.

High yield returns with fixed income potential. Don't miss this wealth 
management opportunity in the decentralized finance space.

Token sale ends soon. Secure your digital wallet access today."""

result2 = analyzer.analyze(
    body=crypto_scam,
    sender='vip@cryptoinvestment-pro.com',
    metadata={'imageCount': 0, 'textLength': len(crypto_scam)}
)

print('\n💎 Advanced Crypto Investment Scam:')
print(f'Score: {result2["score"]}')
print(f'Phishing: {result2["is_phishing"]}')
print(f'Reasons: {result2["reasons"]}')

# Test 3: Social engineering scam
social_engineering = """Professional Network Invitation

Hello,

A colleague recommended you for our exclusive partnership program.
This business opportunity offers commission based revenue sharing 
through our professional network.

Act now - only available to selected candidates. Special invitation 
to join our affiliate program with automated income generation.

Network invitation expires in 48 hours. Secure your position in our 
wealth management system today."""

result3 = analyzer.analyze(
    body=social_engineering,
    sender='invitation@business-network.com',
    metadata={'imageCount': 0, 'textLength': len(social_engineering)}
)

print('\n🤝 Social Engineering Scam:')
print(f'Score: {result3["score"]}')
print(f'Phishing: {result3["is_phishing"]}')
print(f'Reasons: {result3["reasons"]}')

# Test 4: Emotional manipulation scam
emotional_scam = """Last Chance: You Won!

Congratulations you won! You have been selected as our chosen winner 
for an exclusive VIP invitation.

Don't miss out on this special invitation. Only available to winners 
who act now. Limited spots remaining.

This professional network invitation expires soon. Secure your exclusive 
access before it's too late."""

result4 = analyzer.analyze(
    body=emotional_scam,
    sender='winner@exclusive-rewards.com',
    metadata={'imageCount': 0, 'textLength': len(emotional_scam)}
)

print('\n🎯 Emotional Manipulation Scam:')
print(f'Score: {result4["score"]}')
print(f'Phishing: {result4["is_phishing"]}')
print(f'Reasons: {result4["reasons"]}')

print(f'\n📊 Summary:')
print(f'Impersonation: {result1["score"]} pts')
print(f'Crypto Investment: {result2["score"]} pts') 
print(f'Social Engineering: {result3["score"]} pts')
print(f'Emotional Manipulation: {result4["score"]} pts')

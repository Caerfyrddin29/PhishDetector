#!/usr/bin/env python3
import sys
sys.path.append('back')
from analyzer import analyzer

# Test 1: Easy cash scam
easy_cash_email = """Get easy cash today! Click here to start earning $500 per day. 
This is your chance to make money fast. Get paid instantly for simple tasks.
Limited time offer - don't miss out on this opportunity."""

result1 = analyzer.analyze(
    body=easy_cash_email,
    sender='cash@easymoney.xyz',
    metadata={'imageCount': 0, 'textLength': 200}
)

print('Easy Cash Scam Detection:')
print(f'Score: {result1["score"]}')
print(f'Phishing: {result1["is_phishing"]}')
print(f'Reasons: {result1["reasons"]}')

# Test 2: Promotion with click here
promo_email = """Special promotion just for you! Click here to claim your free prize.
Win money now with our exclusive offer. This won't last long!
Click now to get your bonus before it's gone."""

result2 = analyzer.analyze(
    body=promo_email,
    sender='promo@specialoffers.com',
    metadata={'imageCount': 0, 'textLength': 180}
)

print('\nPromotion Scam Detection:')
print(f'Score: {result2["score"]}')
print(f'Phishing: {result2["is_phishing"]}')
print(f'Reasons: {result2["reasons"]}')

# Test 3: Work from home scam
work_home_email = """Work from home and be your own boss! Achieve financial freedom with passive income.
Start today and earn extra cash. Easy money from the comfort of your home."""

result3 = analyzer.analyze(
    body=work_home_email,
    sender='jobs@workfromhome.xyz',
    metadata={'imageCount': 0, 'textLength': 160}
)

print('\nWork From Home Scam Detection:')
print(f'Score: {result3["score"]}')
print(f'Phishing: {result3["is_phishing"]}')
print(f'Reasons: {result3["reasons"]}')

#!/usr/bin/env python3
import sys
sys.path.append('back')
from analyzer import analyzer

# Test the actual crypto scam email content
email_body = """Hello there,

A new exclusive task has dropped! Start your Gemini Exchange Task today to multiply your earnings.

View our guide on how to complete the task and start now to earn $15-45 in 10 minutes.

View the Guide & Start!
Master one of the simplest and most profitable crypto offers available. Complete the entire process in about 10 minutes and walk away with guaranteed profit.

Today is your day."""

result = analyzer.analyze(
    body=email_body,
    sender='newsletter@earnlab.com',
    metadata={'imageCount': 0, 'textLength': 769}
)

print(f'Crypto Scam Detection Results:')
print(f'Score: {result["score"]}')
print(f'Phishing: {result["phishing"]}')
print(f'Reasons: {result["reasons"]}')

# Test with a suspicious crypto link
result2 = analyzer.analyze(
    body=email_body,
    sender='newsletter@earnlab.com',
    links=[{'href': 'http://gemini-exchange-bonus.xyz/start'}],
    metadata={'imageCount': 0, 'textLength': 769}
)

print(f'\nWith Suspicious Link:')
print(f'Score: {result2["score"]}')
print(f'Phishing: {result2["phishing"]}')
print(f'Reasons: {result2["reasons"]}')

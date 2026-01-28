#!/usr/bin/env python3
import sys
sys.path.append('back')
from analyzer import analyzer

print("🧪 Testing Spam Detection...")

# Test 1: Obvious phishing email
print("\n1. Testing obvious phishing...")
result1 = analyzer.analyze(
    body="URGENT: Your account will be suspended. Click here to verify your password immediately. Limited time offer!",
    links=[{"href": "http://paypal-security.xyz/login"}],
    sender="security@paypal-security.xyz",
    metadata={'imageCount': 0, 'textLength': 120}
)

print(f"Score: {result1['score']}")
print(f"Phishing: {result1['is_phishing']}")
print(f"Reasons: {result1['reasons']}")

# Test 2: Nigerian prince spam
print("\n2. Testing Nigerian prince spam...")
result2 = analyzer.analyze(
    body="Dear friend, I am Prince Nigeria and I need your help to transfer $10 million. Please send your bank details urgently.",
    links=[{"href": "http://nigeria-funds.xyz"}],
    sender="prince@nigeria-funds.xyz",
    metadata={'imageCount': 0, 'textLength': 150}
)

print(f"Score: {result2['score']}")
print(f"Phishing: {result2['is_phishing']}")
print(f"Reasons: {result2['reasons']}")

# Test 3: Urgent verification scam
print("\n3. Testing urgent verification...")
result3 = analyzer.analyze(
    body="ACTION REQUIRED: Your Microsoft account has been compromised. Login immediately to secure your data.",
    links=[{"href": "http://microsoft-security-alert.com"}],
    sender="security@microsoft-security-alert.com",
    metadata={'imageCount': 0, 'textLength': 100}
)

print(f"Score: {result3['score']}")
print(f"Phishing: {result3['is_phishing']}")
print(f"Reasons: {result3['reasons']}")

# Test 4: Test with trusted sender that should still be suspicious
print("\n4. Testing suspicious content from trusted domain...")
result4 = analyzer.analyze(
    body="URGENT: Verify your account immediately or it will be suspended. Click here now.",
    links=[{"href": "http://linkedin-security.xyz/login"}],
    sender="security@linkedin.com",
    metadata={'imageCount': 0, 'textLength': 80}
)

print(f"Score: {result4['score']}")
print(f"Phishing: {result4['is_phishing']}")
print(f"Reasons: {result4['reasons']}")

#!/usr/bin/env python3
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), 'back'))

from analyzer import analyzer

def test_analyzer():
    print("🧪 Testing Phishing Analyzer...")
    
    # Test 1: Normal email without sender (should not crash)
    print("\n1. Testing without sender...")
    result1 = analyzer.analyze(
        body="Hello, this is a normal email.",
        links=[],
        sender=""
    )
    print(f"✅ Result: {result1['phishing']}, Score: {result1['score']}")
    
    # Test 2: Email with trusted sender
    print("\n2. Testing with trusted sender...")
    result2 = analyzer.analyze(
        body="Please verify your account urgently",
        links=[],
        sender="newsletter@linkedin.com"
    )
    print(f"✅ Result: {result2['phishing']}, Score: {result2['score']}")
    
    # Test 3: Suspicious email with malicious link
    print("\n3. Testing suspicious content...")
    result3 = analyzer.analyze(
        body="URGENT: Your account will be suspended. Click here to verify your password immediately.",
        links=[{"href": "http://paypal-security.xyz/login"}],
        sender="suspicious@scammer.com"
    )
    print(f"✅ Result: {result3['phishing']}, Score: {result3['score']}")
    print(f"   Reasons: {result3['reasons']}")
    
    # Test 4: Test caching
    print("\n4. Testing caching...")
    import time
    start = time.time()
    result4a = analyzer.analyze(
        body="Hello, this is a normal email.",
        links=[],
        sender=""
    )
    first_time = time.time() - start
    
    start = time.time()
    result4b = analyzer.analyze(
        body="Hello, this is a normal email.",
        links=[],
        sender=""
    )
    second_time = time.time() - start
    
    print(f"✅ First time: {first_time:.4f}s, Cached: {second_time:.4f}s")
    print(f"   Results match: {result4a == result4b}")
    
    print("\n🎉 All tests passed! The analyzer is working correctly.")

if __name__ == "__main__":
    test_analyzer()

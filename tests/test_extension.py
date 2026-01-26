#!/usr/bin/env python3
"""
Test script to simulate extension communication
"""
import requests
import json
import time

def test_scan_simulation():
    print("🧪 Simulating Extension Scan Communication...")
    
    # Test 1: Normal scan
    print("\n1. Testing normal scan...")
    response = requests.post('http://127.0.0.1:5001/analyze', 
        json={
            "body": "Hello, this is a normal email from LinkedIn.",
            "sender": "notifications@linkedin.com",
            "links": [{"href": "https://linkedin.com/posts/123"}],
            "metadata": {
                "imageCount": 0,
                "textLength": 50,
                "isTrusted": False,
                "isReported": False
            }
        },
        timeout=5
    )
    
    if response.status_code == 200:
        result = response.json()
        print(f"✅ Scan result: Score={result['score']}, Phishing={result['phishing']}")
        print(f"   Reasons: {result['reasons']}")
    else:
        print(f"❌ Scan failed: {response.status_code}")
    
    # Test 2: Suspicious scan
    print("\n2. Testing suspicious scan...")
    response = requests.post('http://127.0.0.1:5001/analyze', 
        json={
            "body": "URGENT: Your PayPal account will be suspended. Click here to verify your password immediately.",
            "sender": "security@paypal-security.xyz",
            "links": [{"href": "http://paypal-security.xyz/login"}],
            "metadata": {
                "imageCount": 2,
                "textLength": 30,
                "isTrusted": False,
                "isReported": False
            }
        },
        timeout=5
    )
    
    if response.status_code == 200:
        result = response.json()
        print(f"✅ Scan result: Score={result['score']}, Phishing={result['phishing']}")
        print(f"   Reasons: {result['reasons']}")
        print(f"   Malicious URLs: {result.get('malicious_urls', [])}")
    else:
        print(f"❌ Scan failed: {response.status_code}")
    
    print("\n🎯 Extension communication test completed!")
    print("💡 If the backend responds correctly, the issue is likely:")
    print("   1. Extension needs to be reloaded in Chrome")
    print("   2. Chrome storage permissions issue")
    print("   3. Message passing between content script and popup")

if __name__ == "__main__":
    test_scan_simulation()

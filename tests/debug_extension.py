#!/usr/bin/env python3
"""
Debug script to test what the extension might be sending
"""
import sys
sys.path.append('back')
from analyzer import analyzer

def test_empty_content():
    """Test what happens when extension finds no content"""
    print("🔍 Testing empty content (what extension might be sending)...")
    
    # Test 1: Empty body (if selector fails)
    result1 = analyzer.analyze(
        body="",  # Empty content
        links=[],
        sender="",
        metadata={'imageCount': 0, 'textLength': 0}
    )
    print(f"Empty body - Score: {result1['score']}, Phishing: {result1['phishing']}")
    
    # Test 2: Very short body
    result2 = analyzer.analyze(
        body="Hi",  # Very short content
        links=[],
        sender="test@example.com",
        metadata={'imageCount': 0, 'textLength': 2}
    )
    print(f"Short body - Score: {result2['score']}, Phishing: {result2['phishing']}")
    
    # Test 3: Normal email content
    result3 = analyzer.analyze(
        body="Hello, this is a normal email with some content. How are you doing today?",
        links=[],
        sender="friend@example.com",
        metadata={'imageCount': 0, 'textLength': 60}
    )
    print(f"Normal body - Score: {result3['score']}, Phishing: {result3['phishing']}")

def test_urgency_detection():
    """Test urgency word detection"""
    print("\n🚨 Testing urgency word detection...")
    
    urgency_words = ['urgent', 'verify', 'account', 'password', 'suspended', 'action required', 'login']
    
    for word in urgency_words:
        result = analyzer.analyze(
            body=f"This is {word} message",
            links=[],
            sender="test@example.com",
            metadata={'imageCount': 0, 'textLength': 25}
        )
        print(f"'{word}' - Score: {result['score']}")

if __name__ == "__main__":
    test_empty_content()
    test_urgency_detection()
    
    print("\n💡 If you're seeing 0 scores in the extension, it might be:")
    print("   1. Extension not finding email content (empty body)")
    print("   2. Gmail changed their HTML structure")
    print("   3. Testing on non-Gmail email provider")
    print("   4. Extension permissions issue")

#!/usr/bin/env python3
"""
Test runner for my phishing detector project.

This runs all the tests I wrote to make sure the phishing detection
actually works. It can run all tests at once or specific ones.

Usage:
    python run_tests.py                    # Run all tests
    python run_tests.py specific_test.py    # Run one test file
"""

import os
import sys
import importlib.util
from pathlib import Path

# Add parent directory to path so we can import our modules
sys.path.append(str(Path(__file__).parent.parent))

def run_test_file(test_file):
    """
    Run a single test file and show what happened.
    
    Loads the test file and runs it, showing any errors if they happen.
    
    Args:
        test_file (str): Path to the test file to run
        
    Returns:
        bool: True if test worked, False if it failed
    """
    print(f"\n{'='*50}")
    print(f"Running {test_file}")
    print(f"{'='*50}")
    
    try:
        spec = importlib.util.spec_from_file_location(test_file[:-3], test_file)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return True
    except Exception as e:
        print(f"❌ Error running {test_file}: {e}")
        return False

def main():
    """Main test runner function"""
    test_dir = Path(__file__).parent
    
    
    # Different test categories I made
    categories = {
        'basic': ['test_analyzer.py', 'test_spam_detection.py'],
        'scams': ['test_crypto_scam.py', 'test_easy_cash_scam.py', 'test_sophisticated_scams.py'],
        'advanced': ['test_next_gen.py', 'test_industry_inspired.py'],
        'content': ['test_content_analysis.py', 'test_image_detection.py'],
        'i18n': ['test_french.py'],
        'extension': ['test_extension.py', 'debug_extension.py']
    }
    
    if len(sys.argv) > 1:
        # Run specific category if they asked for one
        category = sys.argv[1].lower()
        if category == 'all':
            # Run all tests
            test_files = list(test_dir.glob('test_*.py')) + list(test_dir.glob('debug_*.py'))
        elif category in categories:
            test_files = [test_dir / f for f in categories[category]]
        else:
            print(f"Unknown category: {category}")
            print(f"Available categories: {', '.join(categories.keys())}, all")
            return
    else:
        # Default: just run basic tests
        test_files = [test_dir / f for f in categories['basic']]
    
    # Run all the tests and count how many pass
    passed = 0
    total = len(test_files)
    
    for test_file in test_files:
        if run_test_file(str(test_file)):
            passed += 1
    
    print(f"\n{'='*50}")
    print(f"Test Results: {passed}/{total} passed")
    print(f"{'='*50}")
    
    if passed == total:
        print("🎉 All tests passed!")
    else:
        print(f"⚠️  {total - passed} tests failed")

if __name__ == '__main__':
    main()

#!/usr/bin/env python3
"""
Test runner for the PhishDetector phishing detection system.

This module provides a comprehensive test execution framework for running
individual test files or the complete test suite. It handles dynamic test
module loading and provides standardized test execution with error handling.

Usage:
    python run_tests.py                    # Run all tests
    python run_tests.py --specific test   # Run specific test category
"""

import os
import sys
import importlib.util
from pathlib import Path

# Add parent directory to path for imports
sys.path.append(str(Path(__file__).parent.parent))

def run_test_file(test_file):
    """
    Execute a single test file with error handling and reporting.
    
    Dynamically loads and executes the specified test module, providing
    clear status reporting and error handling for failed test executions.
    
    Args:
        test_file (str): Path to the test file to execute
        
    Returns:
        bool: True if test executed successfully, False otherwise
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
    """Main test runner"""
    test_dir = Path(__file__).parent
    
    # Test categories
    categories = {
        'basic': ['test_analyzer.py', 'test_spam_detection.py'],
        'scams': ['test_crypto_scam.py', 'test_easy_cash_scam.py', 'test_sophisticated_scams.py'],
        'advanced': ['test_next_gen.py', 'test_industry_inspired.py'],
        'content': ['test_content_analysis.py', 'test_image_detection.py'],
        'i18n': ['test_french.py'],
        'extension': ['test_extension.py', 'debug_extension.py']
    }
    
    if len(sys.argv) > 1:
        # Run specific category
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
        # Default: run basic tests
        test_files = [test_dir / f for f in categories['basic']]
    
    # Run tests
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

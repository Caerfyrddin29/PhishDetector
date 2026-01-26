# PhishDetector Test Suite

This directory contains all test files for the PhishDetector phishing detection system.

## Test Categories

### Basic Tests
- `test_analyzer.py` - Core analyzer functionality
- `test_spam_detection.py` - Basic spam detection

### Scam-Specific Tests
- `test_crypto_scam.py` - Cryptocurrency scam detection
- `test_easy_cash_scam.py` - Easy money scam detection
- `test_sophisticated_scams.py` - Advanced scam patterns

### Advanced Tests
- `test_next_gen.py` - Next-generation detection algorithms
- `test_industry_inspired.py` - Industry-standard patterns

### Content Analysis Tests
- `test_content_analysis.py` - Content-based detection
- `test_image_detection.py` - Image-to-text ratio analysis

### Internationalization Tests
- `test_french.py` - French language scam detection

### Extension Tests
- `test_extension.py` - Browser extension functionality
- `debug_extension.py` - Extension debugging utilities

## Running Tests

### Run all tests:
```bash
python tests/run_tests.py all
```

### Run specific categories:
```bash
python tests/run_tests.py basic
python tests/run_tests.py scams
python tests/run_tests.py advanced
python tests/run_tests.py content
python tests/run_tests.py i18n
python tests/run_tests.py extension
```

### Run individual tests:
```bash
python tests/test_analyzer.py
python tests/test_crypto_scam.py
```

## Test Structure

Each test file is self-contained and can be run independently. Tests are designed to validate:

1. **Detection Accuracy**: Ensure phishing emails are correctly identified
2. **False Positive Rate**: Verify legitimate emails are not flagged
3. **Performance**: Check response times and resource usage
4. **Edge Cases**: Test boundary conditions and unusual inputs

## Adding New Tests

1. Create a new test file following the naming convention `test_*.py`
2. Add it to the appropriate category in `run_tests.py`
3. Follow the existing test patterns and structure
4. Include both positive (phishing) and negative (legitimate) test cases

## Debug Mode

Some tests support debug mode for detailed analysis:
```bash
python tests/test_analyzer.py --debug
```

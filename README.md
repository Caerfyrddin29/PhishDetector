# PhishDetector

A phishing detection system with local processing and Chrome extension integration.

## Overview

PhishDetector is an email security tool that analyzes email content for potential phishing threats. It processes emails locally on your device without sending data to external services, ensuring privacy while providing protection against phishing attacks.

## Features

### Detection Capabilities
- **Multi-layer analysis**: 6-layer detection engine with pattern matching
- **Keyword analysis**: Detects suspicious words and phrases in English and French
- **Link analysis**: Checks URLs against known threat databases
- **Brand impersonation**: Identifies attempts to spoof major brands
- **Content scoring**: Provides risk scores for email analysis
- **Real-time processing**: Fast analysis with intelligent caching

### Technical Features
- **Local processing**: All analysis happens on your device
- **Chrome extension**: Integrates with Gmail for real-time protection
- **Backend API**: Flask server for email analysis
- **SQLite database**: Local threat intelligence storage
- **Comprehensive testing**: Full test suite covering various scenarios

## Quick Start

### Prerequisites
- Python 3.8+
- Chromium browser
- Git

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Start the Backend Server
```bash
# Windows
start_backend.bat

# Manual start
cd back
python app.py
```
The server will start on `http://127.0.0.1:5001`

### 3. Install Chrome Extension
1. Open Chromium and go to `chrome://extensions/`
2. Enable "Developer mode" (top right)
3. Click "Load unpacked" and select the `extension` folder
4. The extension will appear in your browser toolbar

### 4. Verify Installation
```bash
# Run tests to verify everything works
python tests/run_tests.py all
```

## Project Structure

```
PhishDetector/
├── back/                    # Backend API server
│   ├── analyzer.py         # Core detection engine
│   ├── app.py             # Flask API server
│   ├── config.py          # Configuration settings
│   ├── db_manager.py      # Database management
│   └── threat_intel.py    # Threat intelligence
├── extension/              # Chrome extension
│   ├── content.js         # Gmail integration
│   ├── background.js      # Background processing
│   ├── manifest.json      # Extension configuration
│   └── popup.html         # Extension popup
├── tests/                  # Test suite
│   ├── run_tests.py       # Test runner
│   ├── test_analyzer.py   # Core functionality tests
│   ├── test_spam_detection.py # Phishing pattern tests
│   └── debug_extension.py # Extension debugging
├── docs/                   # Documentation
├── requirements.txt        # Python dependencies
├── start_backend.bat       # Quick start script
└── README.md               # This file
```

## Detection System

The system uses a 6-layer analysis approach:

1. **Fast Text Analysis** - Quick keyword scanning for suspicious terms
2. **Linguistic Patterns** - Advanced regex patterns for scam language
3. **Semantic Anomalies** - Detects unnatural conversation patterns
4. **Contextual Analysis** - Finds logical inconsistencies
5. **Sender Behavior** - Analyzes email address characteristics
6. **Link Analysis** - Comprehensive URL threat assessment

### Risk Scoring
- **0-49 points**: Safe (Green banner)
- **50-99 points**: Suspicious (Red banner, lower confidence)
- **100+ points**: High Risk (Red banner, high confidence)

### Attack Types Detected
- Business Email Compromise (BEC)
- Credential harvesting
- Advance fee fraud
- Tech support scams
- Crypto investment scams
- Brand impersonation

## Testing

### Run All Tests
```bash
python tests/run_tests.py all
```

### Run Specific Categories
```bash
python tests/run_tests.py basic      # Core functionality
python tests/run_tests.py scams      # Scam detection
python tests/run_tests.py advanced   # Advanced algorithms
python tests/run_tests.py content    # Content analysis
```

### Individual Tests
```bash
python tests/test_analyzer.py        # Main detection engine
python tests/test_spam_detection.py  # Phishing pattern detection
python tests/debug_extension.py      # Extension debugging
```

## Configuration

### Backend Settings (`back/config.py`)
```python
# Detection threshold
PHISHING_THRESHOLD = 50

# Trusted domains
TRUSTED_DOMAINS = {
    'google.com', 'microsoft.com', 'apple.com',
    'linkedin.com', 'facebook.com', 'amazon.com'
}

# Protected brands
PROTECTED_BRANDS = {
    'paypal': 'paypal.com',
    'microsoft': 'microsoft.com',
    'google': 'google.com'
}

# Suspicious TLDs
DANGEROUS_TLDS = ['.tk', '.ml', '.ga', '.cf', '.top']
```

### Extension Features
- Manual scanning with visual feedback
- User reputation system (trusted/blocked senders)
- Detailed risk scoring and explanations
- Action buttons for trust/report functionality

## Development

### Adding New Detection Patterns
1. Update patterns in `back/analyzer.py`
2. Add test cases in `tests/`
3. Run tests to verify accuracy

### Extending Language Support
1. Add keywords to `config.py` LEXICON
2. Create language-specific tests
3. Update detection logic as needed

## Performance

### Benchmarks
- **Analysis Time**: <50ms average

### Privacy Protection
- All processing happens locally
- No email content leaves your device
- User control over trust/block lists

## Current Status

### Working Features
- Core detection engine with 6-layer analysis
- Chrome extension with Gmail integration
- Backend API with caching
- Database system with threat intelligence

### Known Limitations
- Limited to known attack patterns
- May have false positives with marketing emails (<50% for some of them)
- Database needs regular updates for new threats
- Extension compatibility varies across email providers (only works with gmail for now)

## Contributing

Contributions are welcome! Areas for contribution include:
- New detection patterns (or even ideas)
- Additional language support
- Performance improvements
- Bug fixes and testing
- Documentation improvements (they are not that good actually)

### Development Workflow
1. Fork the repository
2. Create feature branch
3. Commit changes
4. Push to branch
5. Open Pull Request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Disclaimer

This tool is provided for educational and research purposes. While it can help identify potential phishing threats, it should not be relied upon as the sole means of protection against phishing attacks. Always exercise caution when handling suspicious emails.

## Acknowledgments

- Open-source security community for inspiration and techniques
- Various phishing research datasets for testing
- Contributors who help improve the project

# PhishDetector

An open-source phishing detection system with local processing and Chrome extension integration.

## 🎯 What It Is

PhishDetector is a privacy-focused email security tool that analyzes email content for potential phishing threats. It processes emails locally on your device without sending data to external services.

## ✅ Current Features

### Detection Capabilities
- **Pattern-based detection**: Uses regex patterns to identify common phishing techniques
- **Keyword analysis**: Detects suspicious words and phrases
- **Link analysis**: Checks URLs against known threat databases
- **Brand impersonation**: Identifies attempts to spoof major brands
- **Content scoring**: Provides risk scores (0-100) for email analysis

### Technical Features
- **Local processing**: All analysis happens on your device
- **Chrome extension**: Integrates with Gmail and other email clients
- **Backend API**: Flask server for email analysis
- **SQLite database**: Local threat intelligence storage
- **Comprehensive testing**: 15+ test files covering various scenarios

### Supported Languages
- English (primary)
- French (basic keyword support)

## 🏗️ Architecture

```
PhishDetector/
├── back/                    # Backend API server
│   ├── analyzer.py         # Core detection engine
│   ├── app.py             # Flask API server
│   ├── config.py          # Configuration settings
│   ├── db_manager.py      # Database management
│   └── threat_intel.py    # Threat intelligence
├── extension/              # Chrome extension
│   ├── background.js      # Background script
│   ├── content.js         # Content script
│   ├── manifest.json      # Extension manifest
│   └── popup.html         # Extension popup
├── tests/                  # Test suite
│   ├── run_tests.py       # Test runner
│   └── test_*.py          # Individual test files
└── docs/                   # Documentation
```

## ⚡ Quick Start

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

### 3. Load the Chrome Extension
1. Open Chrome and go to `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked" and select the `extension` folder
4. The extension will appear in your browser toolbar

### 4. Use the System
1. Open Gmail or any email client
2. Click the "🛡️ Scan Safety" button in any email
3. View the analysis results

## 🧪 Testing

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

## 📊 Current Limitations

### What It Doesn't Do (Yet)
- **Real-time threat intelligence**: Limited to local database
- **Machine learning**: Uses pattern matching, not trained models
- **Behavioral analysis**: No user behavior tracking
- **Advanced NLP**: Basic keyword analysis only
- **Zero-day detection**: Limited to known patterns

### Known Issues
- May have false positives with legitimate marketing emails
- Limited effectiveness against highly sophisticated attacks
- Database needs regular updates for new threats
- Extension compatibility varies across email providers

## 🔧 Configuration

### Backend Settings (`back/config.py`)
- `PHISHING_THRESHOLD`: Default 50 (adjustable)
- `TRUSTED_DOMAINS`: Whitelisted domains
- `PROTECTED_BRANDS`: Brand protection list
- `DANGEROUS_TLDS`: Suspicious top-level domains

### Extension Settings
- Manual scanning with visual feedback
- User reputation system (trusted/blocked senders)
- Detailed risk scoring and explanations

## 🛠️ Development

### Adding New Detection Patterns
1. Update `analyzer.py` with new regex patterns
2. Add corresponding test cases in `tests/`
3. Run tests to verify accuracy

### Extending Language Support
1. Add keywords to `config.py` LEXICON
2. Create language-specific tests
3. Update detection logic as needed

## 📈 Future Development

This project is actively being developed. Potential improvements include:
- Machine learning integration
- Real-time threat intelligence feeds
- Advanced natural language processing
- Behavioral analysis capabilities
- Enhanced user interface

## 🤝 Contributing

Contributions are welcome! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Areas for Contribution
- New detection patterns
- Additional language support
- Performance improvements
- Bug fixes and testing
- Documentation improvements

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is provided for educational and research purposes. While it can help identify potential phishing threats, it should not be relied upon as the sole means of protection against phishing attacks. Always exercise caution when handling suspicious emails.

## 🙏 Acknowledgments

- Open-source security community for inspiration and techniques
- Various phishing research datasets for testing
- Contributors who help improve the project

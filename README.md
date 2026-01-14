# PhishDetector

A sophisticated phishing detection system with modular Flask backend and Chrome browser extension for Gmail integration.

## Features

### Advanced Detection Engine
- **Multi-layered Analysis**: Sophisticated algorithms with 0-100 risk scoring
- **Brand Protection**: Detects impersonation and typosquatting for PayPal, Google, Microsoft, Amazon, Netflix, Apple
- **Link Analysis**: 
  - Local threat database checking (instant lookup)
  - Deceptive link detection (masked URLs)
  - Typosquatting detection using similarity algorithms
  - High-entropy domain detection
- **Structural Analysis**:
  - Hidden/invisible link detection
  - Image-heavy email with low text detection
- **Obfuscation Detection**: Leetspeak, URL encoding, excessive special characters
- **Linguistic Analysis**: Multi-language pressure keyword detection

### Multilingual Support
- **Languages**: English, Chinese (中文), Arabic (العربية), Russian (Русский), Spanish (Español), French (Français)
- **Auto-detection**: Automatically identifies email language
- **Localized Keywords**: Language-specific suspicious keyword detection

### Browser Extension
- **Gmail Integration**: Seamless one-click scanning in Gmail interface
- **Real-time Alerts**: Color-coded notifications with auto-dismiss
- **Popup Dashboard**: Statistics, charts, and system health monitoring
- **Theme Support**: Light and dark mode options
- **Manual Refresh**: On-demand data updates

## Architecture

### Modular Backend Design
```
back/
├── app.py           # Flask web server (API endpoints)
├── analyzer.py      # Phishing analysis engine
├── config.py        # Configuration settings
├── db_manager.py    # Database management
├── threat_intel.py  # Threat intelligence module
└── phish_cache.db   # Local SQLite database
```

### Chrome Extension
```
extension/
├── manifest.json    # Extension manifest
├── background.js    # Service worker
├── content.js       # Gmail integration
├── popup.html       # Popup UI
└── popup.js         # Popup functionality
```

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Start the Backend Server
```bash
# Option 1: Use the batch file (Windows)
start_backend.bat

# Option 2: Manual start
cd back
python app.py
```
The server will start on `http://127.0.0.1:5001`

### 3. Load the Browser Extension
1. Open Chrome and go to `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked" and select the `extension` folder
4. The extension will appear in your browser toolbar

### 4. Test the System
1. Open Gmail
2. Click the "🛡️ Scan Safety" button in the email view
3. Experience the enhanced interface:
   - **Large score display** (0-100 points)
   - **Color-coded alerts** (🟢 Safe / 🟡 Caution / 🔴 Danger)
   - **Auto-dismiss countdown** (8 seconds)
   - **Malicious URL highlighting**
   - **Real-time chart** in popup dashboard

## 🔧 API Usage

### Analyze Email Content
```bash
curl -X POST http://127.0.0.1:5001/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "body": "Urgent: verify your paypal account now",
    "links": [{"href": "http://paypa1.com", "text": "paypal.com"}],
    "metadata": {
      "sender": "security@paypal-update.com",
      "hasHiddenLinks": false,
      "imageCount": 0,
      "textLength": 100
    }
  }'
```

### Health Check
```bash
curl http://127.0.0.1:5001/test
```

## Scoring System

- **0-29**: Safe (🟢)
- **30-69**: Suspicious (🟡)  
- **70-100**: Phishing (🔴)

### Detection Categories
- **Structural Threats**: Hidden links (100 points), Image-heavy emails (50 points)
- **Link-based Threats**: Blacklisted domains (100 points), Masked URLs (100 points)
- **Brand Impersonation**: Unauthorized brand usage (70-85 points)
- **Linguistic Indicators**: Suspicious keywords (up to 50 points)
- **Technical Threats**: High-entropy domains (30 points), IP URLs (50 points)

## Multilingual Detection

### Supported Languages
- **English**: Full keyword coverage
- **Chinese (中文)**: 紧急, 验证, 暂停, 立即, 重要, 警告
- **Arabic (العربية)**: عاجل, تحقق, معلق, فوري, حرج, إنذار
- **Russian (Русский)**: срочно, проверить, приостановлен, немедленно
- **Spanish (Español)**: urgente, verificar, suspendido, inmediato
- **French (Français)**: urgent, vérifier, suspendu, action requise

### Smart Detection
- **Character-based Recognition**: Unicode pattern matching
- **Context Analysis**: Multiple keyword categories required
- **Obfuscation Handling**: Leetspeak, special characters, URL encoding

## 🛡️ Security Features

- **Local Processing**: All analysis happens locally on your machine
- **Privacy Protection**: No email data sent to external services
- **Real-time Updates**: Threat databases updated automatically
- **Visual Warnings**: Clear indicators for malicious content

## Extension Features

### Email Alerts
- **Score Display**: Large 24px font showing 0-100 risk score
- **Color Coding**: Green/Yellow/Red based on threat level
- **Auto-Dismiss**: Alerts disappear after 8 seconds
- **Click to Dismiss**: Users can close alerts immediately
- **Malicious URLs**: Highlighted in red with full URL display
- **Language Detection**: Shows detected language

### Popup Dashboard
- **System Health**: Backend connection status
- **Average Risk Score**: Running average with progress bar
- **Statistics**: Email scan count and threats blocked
- **Real-time Chart**: Line graph showing last 10 scan scores
- **Theme Support**: Light/dark mode toggle
- **Manual Refresh**: On-demand data updates

## Advanced Detection

### Pattern Recognition
- **URL Shorteners**: Multiple shortener detection
- **IP Address URLs**: Direct IP linking detection
- **Non-standard Ports**: Suspicious port identification
- **Sender Analysis**: Domain pattern checking
- **Attachment Analysis**: Multiple attachment detection

### Brand Protection
- **6+ Major Brands**: PayPal, Google, Microsoft, Amazon, Netflix, Apple
- **Visual Similarity**: Typosquatting detection
- **Domain Patterns**: Suspicious subdomain identification
- **Sender Impersonation**: Email domain verification

## 🛠️ Development

### Project Structure
```
PhishDetector Pro/
├── README.md              # This file
├── requirements.txt       # Python dependencies
├── start_backend.bat      # Windows startup script
├── back/                 # Flask backend
│   ├── app.py           # Main Flask application
│   ├── analyzer.py      # Analysis engine
│   ├── config.py        # Configuration
│   ├── db_manager.py    # Database management
│   ├── threat_intel.py  # Threat intelligence
│   └── phish_cache.db   # SQLite database
├── extension/            # Chrome extension
│   ├── manifest.json    # Extension manifest
│   ├── background.js    # Service worker
│   ├── content.js       # Gmail integration
│   ├── popup.html       # Popup UI
│   └── popup.js         # Popup functionality

```

### Running in Development
1. Start the backend: `cd back && python app.py`
2. Load the extension in Chrome developer mode
3. Open Gmail and test with sample phishing emails

### Testing
```bash
# Test basic functionality
python -c "import requests; print(requests.get('http://127.0.0.1:5001/test').json())"

# Test phishing detection
python -c "
import requests
r = requests.post('http://127.0.0.1:5001/analyze', json={
    'body': 'Urgent: verify your paypal account now',
    'links': [{'href': 'http://paypa1.com', 'text': 'paypal.com'}]
})
print(r.json())
"
```

## 🔧 Troubleshooting

### Common Issues
- **Backend Offline**: Make sure the Flask server is running on port 5001
- **Extension Not Working**: Check Chrome developer console for errors
- **Port Conflicts**: Change port in `app.py` if 5001 is in use
- **Data Not Showing**: Use the refresh button in popup dashboard

### Debug Mode
The backend runs in debug mode by default. Check the console for detailed error messages.

## 📝 Updates

### Recent Changes
- **Modular Architecture**: Split monolithic app into separate `app.py` and `analyzer.py`
- **Improved Popup**: Fixed data display issues and added refresh functionality
- **Enhanced Detection**: Improved multilingual support and obfuscation detection
- **Better UI**: Color-coded alerts and real-time chart updates

### Version History
- **v3.1**: Modular architecture, improved popup UI
- **v3.0**: Multilingual support, advanced obfuscation detection
- **v2.0**: Enhanced UI with charts and statistics
- **v1.0**: Basic phishing detection

## License

This project is for educational and research purposes. Use responsibly and in accordance with applicable laws and regulations.

## 🤝 Contributing

Contributions are welcome! Please ensure all tests pass and follow the existing code style.

---

**PhishDetector** - Advanced phishing protection for Gmail 🛡️

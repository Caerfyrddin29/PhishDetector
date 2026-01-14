# PhishDetector

A phishing detection system with a Flask backend and Chrome browser extension for Gmail integration.

## Features

- **Advanced Phishing Detection**: Multi-layered analysis with sophisticated algorithms
- **Brand Protection**: Detects brand impersonation and typosquatting for major brands (PayPal, Google, Microsoft, Amazon, Netflix, Apple)
- **Link Analysis**:
  - Local threat database checking (instant lookup)
  - Deceptive link detection (masked URLs)
  - Typosquatting detection using similarity algorithms
  - High-entropy domain detection
- **Structural Analysis**:
  - Hidden/invisible link detection
  - Image-heavy email with low text detection
- **Linguistic Analysis**: Pressure keyword detection (urgency, financial, security terms)
- **Browser Extension**: Seamless Gmail integration with one-click scanning
- **Threat Intelligence**: Uses comprehensive phishing databases with auto-updates

## Quick Start

### 1. Install Dependencies
```bash
pip install -r requirements.txt
```

### 2. Start the Backend Server
```bash
cd back
python simple_app.py
```
The server will start on `http://127.0.0.1:5001`

### 3. Load the Browser Extension
1. Open Chrome and go to `chrome://extensions/`
2. Enable "Developer mode"
3. Click "Load unpacked" and select the `extension` folder
4. The extension will appear in your browser toolbar

### 4. Test the Enhanced UI
1. Open Gmail
2. Click the "🛡️ Scan Safety" button that appears in the email view
3. Experience the new enhanced interface with:
   - **Large score display** (0-100 points)
   - **Color-coded alerts** (Green/Yellow/Red)
   - **Auto-dismiss countdown** (8 seconds)
   - **Malicious URL highlighting**
   - **Real-time chart** in popup dashboard

## API Testing

Test the backend directly:
```bash
curl -X POST http://127.0.0.1:5001/analyze \
  -H "Content-Type: application/json" \
  -d '{"body": "Urgent: verify your paypal account now", "links": [{"href": "http://paypa1.com", "text": "paypal.com"}]}'
```

## Project Structure

```
├── back/                    # Flask backend
│   ├── simple_app.py       # Main Flask application
│   ├── analyzer.py         # Phishing analysis logic
│   ├── config.py           # Configuration settings
│   └── db_manager.py       # Database management
├── extension/              # Chrome extension
│   ├── manifest.json      # Extension manifest
│   ├── background.js       # Service worker
│   ├── content.js          # Gmail integration
│   ├── popup.js           # Extension popup
│   └── popup.html         # Popup UI
└── requirements.txt        # Python dependencies
```

## How It Works

### Advanced Detection Engine

The system uses a sophisticated multi-layered approach:

1. **Structural Analysis**
   - Detects invisible link overlays (100 points)
   - Identifies image-heavy emails with minimal text (50 points)

2. **Link Analysis**
   - **Local Database Check**: Instant lookup against 100K+ known phishing domains
   - **Deceptive Text Detection**: Finds masked URLs where display text ≠ actual link
   - **Typosquatting Detection**: Uses similarity algorithms to detect domain spoofing
   - **Entropy Analysis**: Flags suspiciously random-looking domains

3. **Linguistic Analysis**
   - **Urgency Keywords**: "urgent", "verify", "suspended", "action required"
   - **Financial Keywords**: "invoice", "refund", "payment", "transaction"
   - **Security Keywords**: "unauthorized", "detected", "security alert"

4. **Brand Protection**
   - Monitors 6+ major brands (PayPal, Google, Microsoft, Amazon, Netflix, Apple)
   - Detects brand name misuse in unauthorized domains
   - Visual similarity detection for typosquatting

### Scoring System

- **0-69**: Safe (Green)
- **70-100**: Phishing (Red)
- Individual threats can add 20-100 points each
- Maximum score capped at 100

### Backend Architecture

1. **Flask Server**: RESTful API on port 5001
2. **SQLite Database**: Local threat intelligence cache
3. **GitHub Integration**: Auto-updates from phishing databases
4. **Real-time Processing**: Sub-second analysis times

### Extension Integration

1. **Content Script**: Injects scan button into Gmail interface
2. **Background Service**: Handles API communication
3. **Enhanced Visual Alerts**: 
   - Large score display (0-100 points)
   - Color-coded alerts (🟢 Safe / 🟡 Caution / 🔴 Danger)
   - Auto-dismiss countdown (8 seconds)
   - Malicious URL highlighting
4. **Advanced Popup Dashboard**:
   - Average risk score with progress bar
   - Real-time scan history chart
   - Enhanced status indicators
   - Theme support (Light/Dark)
5. **Statistics Tracking**: Maintains scan and threat counts

## New UI Features

### Enhanced Email Alerts
- **Score Display**: Large 24px font showing 0-100 risk score
- **Color Coding**: 
  - 🟢 Green (0-29): Safe emails
  - 🟡 Yellow (30-69): Suspicious emails  
  - 🔴 Red (70-100): Phishing emails
- **Auto-Dismiss**: Alerts disappear after 8 seconds
- **Click to Dismiss**: Users can close alerts immediately
- **Malicious URLs**: Highlighted in red with full URL display
- **Language Detection**: Shows detected language (en, zh, ar, ru, es)
- **Enhanced Readability**: Technical terms simplified for users

### Advanced Popup Dashboard
- **Average Risk Score**: Running average of all scan scores
- **Progress Bar**: Visual representation with color coding
- **Real-time Chart**: Line graph showing last 10 scan scores
- **Enhanced Icons**: Better emoji support and visual indicators
- **Responsive Design**: Wider popup (380px) for better chart display

## Multilingual Support

### Language Detection
- **English**: Full keyword coverage
- **Chinese (中文)**: Urgency, financial, security keywords
- **Arabic (العربية)**: Comprehensive Arabic keyword detection
- **Russian (Русский)**: Cyrillic script support
- **Spanish (Español)**: Latin American Spanish keywords
- **French (Français)**: Complete French keyword detection
- **Auto-Detection**: Automatically identifies email language

### Enhanced Detection Capabilities
- **Balanced Scoring**: Conservative approach to reduce false positives
- **Smart Language Detection**: Character-based recognition (not word-based)
- **Obfuscation Detection**: Leetspeak, special characters, URL encoding
- **Pattern Recognition**: URL shorteners (penalize multiple), IP addresses, suspicious ports
- **Advanced Linguistics**: Context-aware keyword analysis (multiple categories required)
- **UTF-8 Support**: Proper Unicode character handling
- **Sender Analysis**: Suspicious domain patterns, IP address checking
- **Attachment Analysis**: Multiple attachment detection
- **Metadata Collection**: Sender info, attachment count, hidden links

## Security Features

- **Local Processing**: All analysis happens locally on your machine
- **Privacy**: No email data is sent to external services
- **Real-time Updates**: Threat databases are updated automatically
- **Visual Warnings**: Clear indicators for malicious content

## Troubleshooting

- **Backend Offline**: Make sure the Flask server is running on port 5001
- **Extension Not Working**: Check Chrome developer console for errors
- **Port Conflicts**: Change port in `simple_app.py` if 5001 is in use

## Development

To run the full system with debug mode:
1. Start the backend: `cd back && python simple_app.py`
2. Load the extension in Chrome developer mode
3. Open Gmail and test with sample phishing emails

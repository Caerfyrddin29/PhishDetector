# PhishDetector

A simple phishing detector I made for my school project. It checks emails for scams and works with Chrome.

## What This Does

This tool looks at emails and tries to figure out if they're trying to scam you. Everything runs on your computer so your private info stays private.

## Features

### What It Can Do
- **Checks for scam words**: Looks for suspicious stuff in English and French
- **Analyzes links**: Checks if URLs are bad or fake
- **Brand protection**: Catches people pretending to be big companies
- **Risk scoring**: Gives a score from 0-100 for how risky an email is
- **Fast processing**: Works quickly and remembers what it's seen before

### Technical Stuff
- **Local only**: Everything happens on your computer
- **Chrome extension**: Works with Gmail to protect you in real-time
- **Python backend**: Flask server that does the analysis
- **Database**: SQLite for storing bad URLs
- **Lots of tests**: I tested it with many different scam emails

## How to Use It

### What You Need
- Python 3.8 or newer
- Chrome browser
- Basic Python knowledge

### Installation
1. Clone this repo
2. Install the required packages:
   ```bash
   pip install -r requirements.txt
   ```
3. Start the backend server:
   ```bash
   cd back
   python app.py
   ```
4. Load the Chrome extension:
   - Open Chrome and go to `chrome://extensions/`
   - Enable "Developer mode"
   - Click "Load unpacked" and select the `extension` folder
   - Go to Gmail and start using it!

## How It Works

### The Detection Engine
I built a 6-layer system that checks emails:

1. **Text Analysis**: Looks for scam keywords and urgent language
2. **Link Checking**: Analyzes URLs against threat databases
3. **Brand Protection**: Catches fake company impersonation
4. **Language Detection**: Works in English and French
5. **Pattern Recognition**: Finds subtle scam patterns
6. **Risk Scoring**: Calculates a danger score (0-100)

### The Chrome Extension
The extension shows a popup when you open emails in Gmail. It displays:
- Risk score with a visual indicator
- Reasons why an email might be dangerous
- Options to trust, report, or block senders

### The Backend
A simple Flask server that:
- Receives email content from the extension
- Runs the phishing detection algorithms
- Returns results with risk scores and reasons
- Updates local threat intelligence

## Testing

I included lots of tests to make sure it works:

```bash
cd tests
python run_tests.py all
```

The tests cover:
- Basic phishing detection
- Subtle scam patterns
- French and English emails
- Link analysis
- Edge cases

## Project Structure

```
phishdetector/
├── back/                 # Python backend
│   ├── app.py            # Flask server
│   ├── analyzer.py       # Main detection engine
│   ├── config.py         # Configuration settings
│   └── threat_intel.py   # External threat data
├── extension/            # Chrome extension
│   ├── popup.html        # Extension popup UI
│   ├── content.js        # Content script for Gmail
│   ├── background.js     # Background service worker
│   └── manifest.json     # Extension manifest
├── tests/               # Test files
└── README.md           # This file
```

## Configuration

You can change settings in `back/config.py`:

- **Phishing threshold**: Score needed to flag an email as phishing (default: 50)
- **Protected brands**: List of companies to protect from impersonation
- **Trusted domains**: Domains that are always considered safe
- **Dangerous TLDs**: Suspicious top-level domains

## Performance

The system is pretty fast:
- Analysis time: Usually under 0.01 seconds
- Memory usage: Lightweight, runs fine on most computers
- Caching: Remembers emails it's seen before to speed things up

## Privacy

Your privacy is important:
- All processing happens locally on your device
- No data is sent to external servers (except for optional threat intel)
- No tracking or analytics
- Your emails never leave your computer

## Contributing

If you want to help improve this project:
1. Fork it
2. Make your changes
3. Add tests for new features
4. Submit a pull request

## License

This project is for educational purposes. Use it responsibly and at your own risk.

## Acknowledgments

This was my school project for learning about cybersecurity and web development. Thanks to everyone who helped me learn!

---

*Built with ❤️ by a student trying to make the internet safer*

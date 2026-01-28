# Contributing to PhishDetector

Thanks for wanting to contribute! This is a school project, so contributions are pretty informal but still appreciated.

## Quick Start

### What you need
- Python 3.8+
- Git
- Chromium browser (for testing the extension)

### Setup
1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/PhishDetector.git`
3. Go to the project folder: `cd PhishDetector`
4. Install Python stuff: `pip install -r requirements.txt`
5. Start the backend: `python back/app.py`
6. Load the Chrome extension from the `extension/` folder

## Project Structure

```
PhishDetector/
├── back/                    # Backend code
│   ├── analyzer.py         # Main detection logic
│   ├── app.py             # Flask server
│   ├── config.py          # Settings
│   ├── db_manager.py      # Database stuff
│   └── threat_intel.py    # External threat data
├── extension/              # Chrome extension
│   ├── background.js      # Background script
│   ├── content.js         # Gmail integration
│   ├── manifest.json      # Extension config
│   └── popup.html         # Extension popup
├── tests/                  # Test files
│   ├── run_tests.py       # Test runner
│   └── test_*.py          # Individual tests
└── docs/                   # Documentation (kinda)
```

## Testing

### Run all tests
```bash
python tests/run_tests.py all
```

### Run specific tests
```bash
python tests/run_tests.py basic      # Basic functionality
python tests/run_tests.py scams      # Scam detection
python tests/run_tests.py advanced   # Advanced stuff
```

### Adding tests
1. Make test files named `test_*.py`
2. Add them to the right category in `tests/run_tests.py`
3. Test both phishing emails and normal emails
4. Make sure tests pass before submitting

## Code Style

### Python
- Try to follow PEP 8 (but don't stress too much)
- Use clear variable names
- Add docstrings to important functions
- Keep lines under 100 characters if possible

### JavaScript
- Use modern JavaScript (ES6+)
- Keep functions small
- Add comments for confusing parts

## Bug Reports

If you find a bug, please tell me:
- What's wrong
- How to make it happen again
- What should happen vs what actually happens
- Your computer/browser info
- Any error messages
- Example emails if possible

## Feature Ideas

Got ideas for new features? Great!
1. Check if someone already suggested it
2. Explain what the feature should do
3. Why it would be useful
4. If you want to try implementing it, even better

## Development Guidelines

### Main ideas
- **Privacy**: Keep everything local if possible
- **Speed**: Make it fast
- **Accuracy**: Try not to flag too many good emails
- **Simple**: Keep it easy to understand

### Adding new detection patterns
1. Look up current phishing tricks
2. Make test cases
3. Add the patterns to `analyzer.py`
4. Test that it works
5. Update the README

### Extension stuff
- Only ask for permissions you really need
- Don't slow down the browser too much
- Test with different email providers if you can
- Follow Chrome extension security rules

## Performance

### What to aim for
- Try to keep false positives low
- Analysis should be fast (under 500ms)
- Don't use too much memory or CPU

### Testing performance
```bash
# Run performance tests (if they exist)
python tests/test_performance.py

# Check memory usage
python -m memory_profiler back/app.py
```

## Security

### Privacy stuff
- Don't send email content to the cloud
- Process everything locally
- Ask users before collecting any data
- Store user data safely

### Code security
- Check all user inputs
- Be careful with SQL (use parameterized queries)
- Prevent XSS in the extension
- Secure communication between parts

## Documentation

### Keeping docs updated
- Update README.md when you add big features
- Add comments to confusing code
- Document test cases
- Update CHANGELOG for important changes

### When adding features
1. Update the README
2. Add code comments
3. Make test cases
4. Update the changelog

## Pull Request Process

### Before submitting
1. Fork the repo
2. Make a new branch: `git checkout -b feature/your-feature`
3. Make your changes and commit them
4. Run the tests: `python tests/run_tests.py all`
5. Make sure all tests pass
6. Update docs if needed

### Submitting
1. Push to your fork: `git push origin feature/your-feature`
2. Make a Pull Request
3. Explain what you changed
4. Wait for review and fix any issues
5. Merge when approved

### PR template (kinda)
```
What I changed:
- Brief description

Type of change:
- Bug fix
- New feature
- Documentation

Testing:
- All tests pass
- I tested it manually
- Added new tests

Checklist:
- Code looks okay
- Docs updated
- Seems to work fine
```

## Getting Help

### Places to look
- README.md and docs folder
- GitHub issues (search first)
- GitHub Discussions for questions

### Contact
- Create an issue for bugs/feature requests
- Use Discussions for general questions
- For security stuff, message privately

## License

By contributing, you agree your code will be under the same license as the project (MIT).

## Current Focus

This is a learning project, so main priorities are:
1. Making detection better with new patterns
2. Adding more languages (beyond English/French)
3. Making the extension easier to use
4. Improving test coverage
5. Writing better documentation

## Thanks!

Thanks for helping with my school project! Every contribution helps make this better and I'm learning a lot from this. Together we can make email security a bit better for everyone.

---

Note: This is a student project, so things might be a bit messy. Thanks for your patience and for helping improve it!

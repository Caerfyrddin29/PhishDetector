# 🤝 Contributing to PhishDetector

Thank you for your interest in contributing to PhishDetector! This document provides guidelines and information for contributors.

## 🚀 Quick Start

### Prerequisites
- Python 3.8+
- Node.js 16+ (for extension development)
- Git

### Setup
1. Fork the repository
2. Clone your fork: `git clone https://github.com/yourusername/PhishDetector.git`
3. Navigate to the project: `cd PhishDetector`
4. Install Python dependencies: `pip install -r requirements.txt`
5. Start the backend: `python back/app.py`
6. Load the Chrome extension from the `extension/` directory

## 🏗️ Project Structure

```
PhishDetector/
├── back/                    # Backend API server
│   ├── analyzer.py         # Core detection engine
│   ├── app.py             # Flask API server
│   ├── config.py          # Configuration
│   ├── db_manager.py      # Database management
│   └── threat_intel.py    # Threat intelligence
├── extension/              # Chrome extension
│   ├── background.js      # Background script
│   ├── content.js         # Content script
│   ├── manifest.json      # Extension manifest
│   └── popup.html         # Extension UI
├── tests/                  # Test suite
│   ├── run_tests.py       # Test runner
│   └── test_*.py          # Test files
└── docs/                   # Documentation
```

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

### Adding New Tests
1. Create test files following the naming convention `test_*.py`
2. Add to appropriate category in `tests/run_tests.py`
3. Include both positive (phishing) and negative (legitimate) test cases
4. Ensure all tests pass before submitting PR

## 📝 Code Style

### Python
- Follow PEP 8 style guidelines
- Use meaningful variable and function names
- Add docstrings for all functions and classes
- Keep lines under 100 characters
- Use type hints where appropriate

### JavaScript
- Use modern ES6+ syntax
- Follow consistent naming conventions
- Add comments for complex logic
- Keep functions small and focused

## 🐛 Bug Reports

When filing bug reports, please include:
- **Clear description** of the issue
- **Steps to reproduce** the problem
- **Expected vs actual behavior**
- **Environment details** (OS, browser, Python version)
- **Relevant logs** or error messages
- **Sample emails** that demonstrate the issue (if applicable)

## ✨ Feature Requests

We welcome feature requests! Please:
1. **Check existing issues** to avoid duplicates
2. **Provide clear description** of the feature
3. **Explain the use case** and why it's valuable
4. **Consider implementation complexity**
5. **Offer to help implement** if possible

## 🔧 Development Guidelines

### Core Principles
- **Privacy First**: All processing should be local when possible
- **Transparency**: Users should understand why emails are flagged
- **Performance**: Keep analysis fast and efficient
- **Accuracy**: Minimize false positives and negatives
- **User Experience**: Make the system intuitive and helpful

### Adding New Detection Patterns
1. **Research**: Study current phishing techniques and patterns
2. **Test**: Create comprehensive test cases
3. **Implement**: Add patterns to `analyzer.py`
4. **Validate**: Ensure accuracy and performance
5. **Document**: Update README and add comments

### Extension Development
- **Permissions**: Only request necessary permissions
- **Performance**: Minimize impact on browser performance
- **Compatibility**: Test across different email providers
- **Security**: Follow Chrome extension security best practices

## 📊 Performance Guidelines

### Target Metrics
- **Detection Accuracy**: Aim for high true positive rate
- **False Positive Rate**: Keep false positives minimal
- **Response Time**: <500ms per email analysis
- **Memory Usage**: <512MB for backend
- **CPU Usage**: Reasonable resource consumption

### Testing Performance
```bash
# Run performance tests
python tests/test_performance.py

# Profile memory usage
python -m memory_profiler back/app.py

# Benchmark detection speed
python tests/benchmark.py
```

## 🔒 Security Considerations

### Data Privacy
- **No cloud dependencies** for core functionality
- **Local processing** of sensitive email content
- **User consent** for any data collection
- **Secure storage** of user preferences and data

### Code Security
- **Input validation** for all user inputs
- **SQL injection prevention** in database operations
- **XSS prevention** in extension code
- **Secure communication** between components

## 📚 Documentation

### Updating Documentation
- **README.md**: Keep installation and setup instructions current
- **API docs**: Document new endpoints and parameters
- **Code comments**: Explain complex algorithms and logic
- **Test docs**: Document test cases and expected results

### Adding New Features
1. **Update README** with feature description
2. **Add inline documentation** to code
3. **Create test cases** with clear documentation
4. **Update CHANGELOG** with version notes

## 🔄 Pull Request Process

### Before Submitting
1. **Fork** the repository
2. **Create feature branch**: `git checkout -b feature/amazing-feature`
3. **Make changes** and commit with clear messages
4. **Run tests**: `python tests/run_tests.py all`
5. **Ensure all tests pass**
6. **Update documentation** as needed

### Submitting PR
1. **Push to fork**: `git push origin feature/amazing-feature`
2. **Create Pull Request** with clear title and description
3. **Link related issues** in the PR description
4. **Wait for review** and address feedback
5. **Merge** after approval

### PR Template
```markdown
## Description
Brief description of changes made.

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] All tests pass
- [ ] New tests added
- [ ] Manual testing completed

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-review completed
- [ ] Documentation updated
- [ ] Performance considered
```

## 🏆 Recognition

### Contributors
- All contributors are recognized in the README
- Top contributors may be offered maintainer access
- Exceptional contributions are highlighted in releases

### Release Notes
- Contributors are credited in each release
- Notable contributions are featured in project updates
- Community feedback is acknowledged and valued

## 📞 Getting Help

### Resources
- **Documentation**: Check the project README and docs folder
- **Issues**: Search existing GitHub issues
- **Discussions**: Use GitHub Discussions for questions
- **Wiki**: Community-maintained knowledge base (if available)

### Contact
- **Issues**: For bug reports and feature requests
- **Discussions**: For general questions and ideas
- **Security**: For security-related concerns (private)

## 📄 License

By contributing to this project, you agree that your contributions will be licensed under the same license as the project. Please see the [LICENSE](LICENSE) file for details.

## 🎯 Current Project Focus

This is an early-stage project with the following priorities:
1. **Improving detection accuracy** through better patterns
2. **Expanding language support** beyond English/French
3. **Enhancing user experience** and interface
4. **Building comprehensive test coverage**
5. **Creating educational documentation**

## 🙏 Thank You!

Thank you for contributing to PhishDetector! Your contributions help make email security more accessible and effective for everyone. Together, we're building a more secure digital world! 🛡️

---

**Note**: This project is currently in active development. We appreciate your patience as we improve the system and welcome all constructive contributions!

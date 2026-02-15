# Contributing to GitAntivirus

Thank you for your interest in contributing to GitAntivirus! This document provides guidelines and instructions for contributing.

## 🤝 How to Contribute

### Reporting Bugs

If you find a bug:

1. Check if the issue already exists in [GitHub Issues](https://github.com/SolanaRemix/GitAntivirus/issues)
2. If not, create a new issue with:
   - Clear title and description
   - Steps to reproduce
   - Expected vs actual behavior
   - Your environment details (OS, Node version, etc.)

### Suggesting Features

We welcome feature suggestions! Please:

1. Check existing issues for similar suggestions
2. Create a new issue with the `enhancement` label
3. Describe the feature and its benefits
4. Provide examples of how it would work

### Pull Requests

1. **Fork the repository**
   ```bash
   git clone https://github.com/SolanaRemix/GitAntivirus.git
   cd GitAntivirus
   ```

2. **Create a branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

3. **Make your changes**
   - Follow the code style guidelines below
   - Add tests if applicable
   - Update documentation as needed

4. **Test your changes**
   ```bash
   npm test
   npm run scan
   ```

5. **Commit your changes**
   ```bash
   git commit -m "Add feature: description"
   ```

6. **Push to your fork**
   ```bash
   git push origin feature/your-feature-name
   ```

7. **Create a Pull Request**
   - Provide a clear description of the changes
   - Reference any related issues
   - Wait for review and address feedback

## 📝 Code Style Guidelines

### JavaScript

- Use ES6+ features
- Use meaningful variable and function names
- Add JSDoc comments for functions
- Keep functions focused and small
- Use async/await for asynchronous code

### Example:

```javascript
/**
 * Scan content for secrets
 * @param {string} content - Content to scan
 * @param {string} filename - File name
 * @returns {Array} Array of findings
 */
scan(content, filename) {
  // Implementation
}
```

## 🔍 Adding New Scanners

To add a new security scanner:

1. Create a new file in `scanner/` directory
2. Implement the scanner class with a `scan()` method
3. Add tests for the scanner
4. Update `index.js` to include the new scanner
5. Update documentation

### Scanner Template:

```javascript
class MyScanner {
  constructor() {
    // Initialize patterns, rules, etc.
  }

  /**
   * Scan content for issues
   * @param {string} content - Content to scan
   * @param {string} filename - File name
   * @returns {Array} Array of findings
   */
  scan(content, filename) {
    const findings = [];
    
    // Scan logic here
    
    return findings;
  }
}

module.exports = MyScanner;
```

## 🛠️ Adding New Auto-Fixes

To add a new auto-fix capability:

1. Add fix method in `fixes/autofix.js`
2. Register the method in `getFixMethod()`
3. Test the fix thoroughly
4. Document the fix behavior

## 📚 Documentation

When contributing:

- Update README.md if adding features
- Add JSDoc comments to new functions
- Update configuration examples if needed
- Include usage examples for new features

## 🧪 Testing

Before submitting a PR:

1. Test your changes locally
2. Run the scanner on various repositories
3. Verify auto-fixes work correctly
4. Check for edge cases

## 🔐 Security

If you discover a security vulnerability:

1. **DO NOT** open a public issue
2. Email security@cyberai.ecosystem with details
3. Allow time for the issue to be addressed
4. We'll credit you in the security advisory

## 💡 Development Setup

```bash
# Clone the repository
git clone https://github.com/SolanaRemix/GitAntivirus.git
cd GitAntivirus

# Install dependencies (when added)
npm install

# Run the scanner
node index.js /path/to/test/repo

# Run with auto-fix
node index.js /path/to/test/repo --fix
```

## 📋 Checklist for Contributors

Before submitting a PR, ensure:

- [ ] Code follows style guidelines
- [ ] Comments and documentation added
- [ ] Changes tested locally
- [ ] No sensitive data in commits
- [ ] Commit messages are clear
- [ ] PR description explains changes
- [ ] Related issues referenced

## 🌟 Recognition

Contributors will be:

- Listed in our contributors page
- Mentioned in release notes
- Invited to join our Discord community

## 📞 Questions?

- Open a discussion in GitHub Discussions
- Join our Discord server
- Email support@cyberai.ecosystem

Thank you for helping make GitAntivirus better! 🛡️

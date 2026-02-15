/**
 * GitAntivirus - Secret Scanner
 * Detects exposed credentials, API keys, tokens, and other sensitive data
 */

class SecretScanner {
  constructor() {
    // Pattern definitions for various secret types
    this.patterns = {
      aws_access_key: {
        pattern: /AKIA[0-9A-Z]{16}/g,
        name: 'AWS Access Key',
        severity: 'critical'
      },
      aws_secret_key: {
        pattern: /aws_secret_access_key\s*=\s*['"]?([A-Za-z0-9/+=]{40})['"]?/gi,
        name: 'AWS Secret Key',
        severity: 'critical'
      },
      github_token: {
        pattern: /ghp_[a-zA-Z0-9]{36}/g,
        name: 'GitHub Personal Access Token',
        severity: 'critical'
      },
      github_oauth: {
        pattern: /gho_[a-zA-Z0-9]{36}/g,
        name: 'GitHub OAuth Token',
        severity: 'critical'
      },
      slack_token: {
        pattern: /xox[baprs]-[0-9]{10,12}-[0-9]{10,12}-[a-zA-Z0-9]{24,32}/g,
        name: 'Slack Token',
        severity: 'high'
      },
      slack_webhook: {
        pattern: /https:\/\/hooks\.slack\.com\/services\/T[a-zA-Z0-9_]+\/B[a-zA-Z0-9_]+\/[a-zA-Z0-9_]+/g,
        name: 'Slack Webhook',
        severity: 'high'
      },
      google_api_key: {
        pattern: /AIza[0-9A-Za-z\-_]{35}/g,
        name: 'Google API Key',
        severity: 'high'
      },
      google_oauth: {
        pattern: /[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com/g,
        name: 'Google OAuth ID',
        severity: 'high'
      },
      private_key: {
        pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/g,
        name: 'Private Key',
        severity: 'critical'
      },
      jwt_token: {
        pattern: /eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*/g,
        name: 'JWT Token',
        severity: 'medium'
      },
      generic_api_key: {
        pattern: /['"]?api[_-]?key['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]?/gi,
        name: 'Generic API Key',
        severity: 'high'
      },
      generic_secret: {
        pattern: /['"]?secret['"]?\s*[:=]\s*['"]([a-zA-Z0-9_\-]{20,})['"]?/gi,
        name: 'Generic Secret',
        severity: 'medium'
      },
      password: {
        pattern: /['"]?password['"]?\s*[:=]\s*['"]([^'"]{8,})['"]?/gi,
        name: 'Hardcoded Password',
        severity: 'high'
      },
      database_url: {
        pattern: /(postgres|mysql|mongodb):\/\/[^:]+:[^@]+@[^\/]+\/[^\s"']*/gi,
        name: 'Database Connection String',
        severity: 'critical'
      },
      stripe_key: {
        pattern: /sk_live_[0-9a-zA-Z]{24,}/g,
        name: 'Stripe Secret Key',
        severity: 'critical'
      },
      mailgun_api_key: {
        pattern: /key-[0-9a-zA-Z]{32}/g,
        name: 'Mailgun API Key',
        severity: 'medium'
      },
      twilio_api_key: {
        pattern: /SK[0-9a-fA-F]{32}/g,
        name: 'Twilio API Key',
        severity: 'high'
      }
    };

    // High-entropy string detector (for unknown secrets)
    this.entropyThreshold = 4.5;
  }

  /**
   * Scan content for exposed secrets
   * @param {string} content - File content to scan
   * @param {string} filename - Name of the file being scanned
   * @returns {Array} Array of detected secrets
   */
  scan(content, filename) {
    const findings = [];

    // Check each pattern
    for (const [type, config] of Object.entries(this.patterns)) {
      const matches = content.matchAll(config.pattern);
      
      for (const match of matches) {
        const lineNumber = this.getLineNumber(content, match.index);
        const context = this.getContext(content, match.index);
        
        findings.push({
          type,
          name: config.name,
          severity: config.severity,
          file: filename,
          line: lineNumber,
          match: this.redactSecret(match[0]),
          context,
          recommendation: this.getRecommendation(type)
        });
      }
    }

    // Check for high-entropy strings (potential secrets)
    const highEntropyFindings = this.detectHighEntropy(content, filename);
    findings.push(...highEntropyFindings);

    return findings;
  }

  /**
   * Calculate Shannon entropy of a string
   * @param {string} str - String to analyze
   * @returns {number} Entropy value
   */
  calculateEntropy(str) {
    const len = str.length;
    const frequencies = {};
    
    for (let i = 0; i < len; i++) {
      const char = str[i];
      frequencies[char] = (frequencies[char] || 0) + 1;
    }
    
    let entropy = 0;
    for (const char in frequencies) {
      const p = frequencies[char] / len;
      entropy -= p * Math.log2(p);
    }
    
    return entropy;
  }

  /**
   * Detect high-entropy strings that might be secrets
   * @param {string} content - File content
   * @param {string} filename - Filename
   * @returns {Array} Detected high-entropy strings
   */
  detectHighEntropy(content, filename) {
    const findings = [];
    // Look for long alphanumeric strings
    const regex = /['"]([a-zA-Z0-9+/=_-]{32,})['"]|=\s*([a-zA-Z0-9+/=_-]{32,})/g;
    const matches = content.matchAll(regex);
    
    for (const match of matches) {
      const candidate = match[1] || match[2];
      const entropy = this.calculateEntropy(candidate);
      
      if (entropy >= this.entropyThreshold && candidate.length >= 32) {
        const lineNumber = this.getLineNumber(content, match.index);
        const context = this.getContext(content, match.index);
        
        findings.push({
          type: 'high_entropy',
          name: 'High Entropy String (Potential Secret)',
          severity: 'medium',
          file: filename,
          line: lineNumber,
          match: this.redactSecret(candidate),
          context,
          entropy: entropy.toFixed(2),
          recommendation: 'Review this string. If it\'s a secret, move it to environment variables.'
        });
      }
    }
    
    return findings;
  }

  /**
   * Get line number from character index
   * @param {string} content - File content
   * @param {number} index - Character index
   * @returns {number} Line number
   */
  getLineNumber(content, index) {
    return content.substring(0, index).split('\n').length;
  }

  /**
   * Get context around a match
   * @param {string} content - File content
   * @param {number} index - Character index
   * @returns {string} Context snippet
   */
  getContext(content, index) {
    const lines = content.split('\n');
    const lineNum = this.getLineNumber(content, index);
    const start = Math.max(0, lineNum - 2);
    const end = Math.min(lines.length, lineNum + 1);
    
    return lines.slice(start, end).join('\n');
  }

  /**
   * Redact secret for display
   * @param {string} secret - Secret to redact
   * @returns {string} Redacted secret
   */
  redactSecret(secret) {
    if (secret.length <= 8) {
      return '***';
    }
    const start = secret.substring(0, 4);
    const end = secret.substring(secret.length - 4);
    return `${start}...${end}`;
  }

  /**
   * Get remediation recommendation for secret type
   * @param {string} type - Secret type
   * @returns {string} Recommendation
   */
  getRecommendation(type) {
    const recommendations = {
      aws_access_key: 'Revoke this key immediately in AWS IAM and rotate. Use environment variables or AWS Secrets Manager.',
      aws_secret_key: 'Revoke this key immediately in AWS IAM and rotate. Use environment variables or AWS Secrets Manager.',
      github_token: 'Revoke this token in GitHub Settings and generate a new one. Use GitHub Secrets for Actions.',
      github_oauth: 'Revoke this OAuth token in GitHub Settings. Use secure storage mechanisms.',
      private_key: 'Remove from repository immediately. Use secure key management systems.',
      database_url: 'Move to environment variables. Never commit database credentials.',
      stripe_key: 'Rotate this key in Stripe dashboard. Use environment variables.',
      password: 'Remove hardcoded password. Use environment variables or secure vaults.',
      generic_api_key: 'Move to environment variables and rotate the key if exposed.',
      generic_secret: 'Move to environment variables or secure secret management system.'
    };
    
    return recommendations[type] || 'Review and move to secure storage if this is a sensitive value.';
  }
}

module.exports = SecretScanner;

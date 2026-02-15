/**
 * GitAntivirus - Code Scanner
 * Analyzes JavaScript and JSON code for security vulnerabilities
 */

class CodeScanner {
  constructor() {
    // Security vulnerability patterns
    this.vulnerabilityPatterns = {
      sql_injection: {
        patterns: [
          /execute\s*\(\s*['"`].*\$\{.*\}.*['"`]/gi,
          /query\s*\(\s*['"`].*\+.*['"`]/gi,
          /sql\s*=\s*['"`].*\+.*['"`]/gi
        ],
        name: 'SQL Injection Risk',
        severity: 'critical',
        description: 'String concatenation in SQL queries can lead to SQL injection'
      },
      xss_vulnerability: {
        patterns: [
          /innerHTML\s*=\s*[^'"]/gi,
          /\.html\s*\(\s*[^'"]/gi,
          /document\.write\s*\(/gi,
          /eval\s*\(/gi
        ],
        name: 'XSS Vulnerability',
        severity: 'high',
        description: 'Potential cross-site scripting vulnerability'
      },
      command_injection: {
        patterns: [
          /exec\s*\(\s*['"`].*\$\{.*\}.*['"`]/gi,
          /spawn\s*\(\s*['"`].*\+.*['"`]/gi,
          /execSync\s*\(\s*['"`].*\$\{.*\}.*['"`]/gi
        ],
        name: 'Command Injection Risk',
        severity: 'critical',
        description: 'User input in system commands can lead to command injection'
      },
      path_traversal: {
        patterns: [
          /readFile\s*\(\s*.*\+.*\)/gi,
          /writeFile\s*\(\s*.*\+.*\)/gi,
          /fs\.\w+\s*\(\s*req\.(body|params|query)/gi
        ],
        name: 'Path Traversal Risk',
        severity: 'high',
        description: 'Unvalidated file paths can lead to unauthorized file access'
      },
      weak_crypto: {
        patterns: [
          /createHash\s*\(\s*['"]md5['"]/gi,
          /createHash\s*\(\s*['"]sha1['"]/gi,
          /\.update\s*\(\s*['"]DES['"]/gi
        ],
        name: 'Weak Cryptography',
        severity: 'medium',
        description: 'Using deprecated or weak cryptographic algorithms'
      },
      insecure_random: {
        patterns: [
          /Math\.random\s*\(\s*\).*password/gi,
          /Math\.random\s*\(\s*\).*token/gi,
          /Math\.random\s*\(\s*\).*secret/gi
        ],
        name: 'Insecure Random Number Generation',
        severity: 'high',
        description: 'Math.random() is not cryptographically secure'
      },
      regex_dos: {
        patterns: [
          /new RegExp\s*\(\s*req\.(body|params|query)/gi,
          /\.match\s*\(\s*new RegExp\s*\(.*\+/gi
        ],
        name: 'ReDoS Vulnerability',
        severity: 'medium',
        description: 'User-controlled regex can cause denial of service'
      },
      unsafe_deserialization: {
        patterns: [
          /JSON\.parse\s*\(\s*req\.(body|params|query)/gi,
          /eval\s*\(\s*JSON\.stringify/gi,
          /Function\s*\(/gi
        ],
        name: 'Unsafe Deserialization',
        severity: 'high',
        description: 'Deserializing untrusted data can lead to code execution'
      }
    };

    // Code quality issues
    this.codeQualityPatterns = {
      console_log: {
        pattern: /console\.(log|debug|info|warn|error)/gi,
        name: 'Console Statement in Production',
        severity: 'low',
        description: 'Console statements should be removed in production code'
      },
      debugger: {
        pattern: /debugger;/gi,
        name: 'Debugger Statement',
        severity: 'low',
        description: 'Debugger statements should not be in production code'
      },
      todo_comments: {
        pattern: /\/\/\s*TODO|\/\/\s*FIXME|\/\*\s*TODO|\/\*\s*FIXME/gi,
        name: 'TODO/FIXME Comment',
        severity: 'info',
        description: 'Unresolved TODO or FIXME comment'
      }
    };
  }

  /**
   * Scan code for security vulnerabilities
   * @param {string} content - File content
   * @param {string} filename - Name of the file
   * @returns {Array} Array of findings
   */
  scan(content, filename) {
    const findings = [];

    // Check for security vulnerabilities
    for (const [type, config] of Object.entries(this.vulnerabilityPatterns)) {
      for (const pattern of config.patterns) {
        const matches = content.matchAll(pattern);
        
        for (const match of matches) {
          const lineNumber = this.getLineNumber(content, match.index);
          const context = this.getContext(content, match.index);
          
          findings.push({
            type,
            name: config.name,
            severity: config.severity,
            file: filename,
            line: lineNumber,
            code: match[0].trim(),
            context,
            description: config.description,
            recommendation: this.getRecommendation(type),
            autoFixable: false
          });
        }
      }
    }

    // Check for code quality issues (only if it's a production file)
    if (!filename.includes('.test.') && !filename.includes('.spec.')) {
      for (const [type, config] of Object.entries(this.codeQualityPatterns)) {
        const matches = content.matchAll(config.pattern);
        
        for (const match of matches) {
          const lineNumber = this.getLineNumber(content, match.index);
          
          findings.push({
            type,
            name: config.name,
            severity: config.severity,
            file: filename,
            line: lineNumber,
            code: match[0].trim(),
            description: config.description,
            recommendation: 'Remove or replace before production deployment',
            autoFixable: type === 'console_log' || type === 'debugger'
          });
        }
      }
    }

    return findings;
  }

  /**
   * Scan JSON files for issues
   * @param {string} content - JSON file content
   * @param {string} filename - Filename
   * @returns {Array} Findings
   */
  scanJSON(content, filename) {
    const findings = [];

    try {
      const data = JSON.parse(content);

      // Check for credentials in JSON
      const credentialKeys = ['password', 'apiKey', 'api_key', 'secret', 'token', 'accessToken', 'privateKey'];
      
      this.scanObject(data, filename, credentialKeys, findings);

    } catch (e) {
      findings.push({
        type: 'invalid_json',
        name: 'Invalid JSON',
        severity: 'medium',
        file: filename,
        description: 'JSON file is malformed',
        error: e.message,
        recommendation: 'Fix JSON syntax errors',
        autoFixable: false
      });
    }

    return findings;
  }

  /**
   * Recursively scan object for credentials
   * @param {Object} obj - Object to scan
   * @param {string} filename - Filename
   * @param {Array} keys - Keys to check
   * @param {Array} findings - Findings array
   * @param {string} path - Current path in object
   */
  scanObject(obj, filename, keys, findings, path = '') {
    if (typeof obj !== 'object' || obj === null) {
      return;
    }

    for (const [key, value] of Object.entries(obj)) {
      const currentPath = path ? `${path}.${key}` : key;

      // Check if key matches credential pattern
      if (keys.some(k => key.toLowerCase().includes(k.toLowerCase()))) {
        if (typeof value === 'string' && value.length > 0) {
          findings.push({
            type: 'json_credentials',
            name: 'Potential Credential in JSON',
            severity: 'high',
            file: filename,
            path: currentPath,
            description: `Key "${key}" appears to contain credentials`,
            recommendation: 'Move credentials to environment variables',
            autoFixable: false
          });
        }
      }

      // Recurse for nested objects
      if (typeof value === 'object' && value !== null) {
        this.scanObject(value, filename, keys, findings, currentPath);
      }
    }
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
   * Get remediation recommendation
   * @param {string} type - Vulnerability type
   * @returns {string} Recommendation
   */
  getRecommendation(type) {
    const recommendations = {
      sql_injection: 'Use parameterized queries or prepared statements. Never concatenate user input into SQL queries.',
      xss_vulnerability: 'Sanitize user input before rendering. Use textContent instead of innerHTML, or use a sanitization library.',
      command_injection: 'Avoid executing system commands with user input. If necessary, use allowlists and proper escaping.',
      path_traversal: 'Validate and sanitize file paths. Use path.join() and check if resolved path is within allowed directory.',
      weak_crypto: 'Use strong algorithms like SHA-256 or SHA-512. Avoid MD5 and SHA-1.',
      insecure_random: 'Use crypto.randomBytes() or crypto.getRandomValues() for security-sensitive random values.',
      regex_dos: 'Validate regex patterns and set timeouts. Avoid user-controlled regex when possible.',
      unsafe_deserialization: 'Validate and sanitize all input before parsing. Avoid eval() and Function() constructor.'
    };
    
    return recommendations[type] || 'Review and fix this security issue.';
  }
}

module.exports = CodeScanner;

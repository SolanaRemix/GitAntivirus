/**
 * GitAntivirus - Detection Rules
 * Pattern-based rules for identifying security threats
 */

exports.rules = [
  {
    name: 'Private Key Exposure',
    pattern: /0x[a-fA-F0-9]{64}/,
    severity: 'critical'
  },
  {
    name: 'PEM Private Key',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----/,
    severity: 'critical'
  },
  {
    name: 'AWS Access Key',
    pattern: /AKIA[0-9A-Z]{16}/,
    severity: 'critical'
  },
  {
    name: 'GitHub Token',
    pattern: /ghp_[a-zA-Z0-9]{36}/,
    severity: 'critical'
  },
  {
    name: 'Stripe Secret Key',
    pattern: /sk_live_[0-9a-zA-Z]{24,}/,
    severity: 'critical'
  },
  {
    name: 'Database Connection String',
    pattern: /(postgres|mysql|mongodb):\/\/[^:]+:[^@]+@/i,
    severity: 'critical'
  },
  {
    name: 'API Key Leak',
    pattern: /(api_key|apikey|api-key)\s*[:=]\s*['"]?[A-Za-z0-9\-_]{16,}/i,
    severity: 'high'
  },
  {
    name: 'Generic Secret',
    pattern: /secret\s*[:=]\s*['"][A-Za-z0-9\-_]{16,}['"]/i,
    severity: 'high'
  },
  {
    name: 'Hardcoded Password',
    // Require the value to contain no whitespace (real passwords don't read as sentences)
    pattern: /password\s*[:=]\s*['"][^\s'"]{8,}['"]/i,
    severity: 'high'
  },
  {
    name: 'Base64 Obfuscation',
    pattern: /atob\s*\(|Buffer\.from\(.+['"]base64['"]\)/,
    severity: 'high'
  },
  {
    name: 'Suspicious Web3 Drain',
    pattern: /(transfer|send)\(.+allBalance/i,
    severity: 'critical'
  },
  {
    name: 'Eval Usage',
    pattern: /\beval\s*\(/,
    severity: 'medium'
  },
  {
    name: 'Function Constructor (Code Injection)',
    pattern: /new\s+Function\s*\(/,
    severity: 'medium'
  }
];

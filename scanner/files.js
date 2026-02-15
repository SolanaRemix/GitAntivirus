/**
 * GitAntivirus - File Scanner
 * Analyzes files for sensitive content and misconfigurations
 */

const path = require('path');

class FileScanner {
  constructor() {
    // Sensitive file patterns
    this.sensitiveFiles = [
      '.env',
      '.env.local',
      '.env.development',
      '.env.production',
      '.env.test',
      'secrets.yml',
      'secrets.yaml',
      'secrets.json',
      'config/secrets.yml',
      'credentials.json',
      '.aws/credentials',
      '.aws/config',
      'id_rsa',
      'id_dsa',
      'id_ecdsa',
      'id_ed25519',
      '*.pem',
      '*.key',
      '*.p12',
      '*.pfx',
      'keystore.jks',
      '.htpasswd',
      'wp-config.php',
      'database.yml'
    ];

    // Files that should be in .gitignore
    this.shouldBeIgnored = [
      '.env',
      '.env.local',
      '.env.*.local',
      '*.pem',
      '*.key',
      'id_rsa*',
      'credentials.json',
      'secrets.json',
      'config/secrets.yml'
    ];

    // Configuration files that often contain sensitive data
    this.configFiles = [
      'config.json',
      'config.yml',
      'config.yaml',
      'settings.json',
      'appsettings.json',
      'web.config',
      'application.properties',
      'application.yml'
    ];
  }

  /**
   * Scan a file for security issues
   * @param {string} filename - Path to the file
   * @param {string} content - File content
   * @param {boolean} isTracked - Whether file is tracked by git
   * @returns {Array} Array of findings
   */
  scan(filename, content, isTracked = true) {
    const findings = [];
    const basename = path.basename(filename);

    // Check if sensitive file is tracked
    if (this.isSensitiveFile(filename) && isTracked) {
      findings.push({
        type: 'sensitive_file',
        name: 'Sensitive File Tracked in Git',
        severity: 'critical',
        file: filename,
        description: `${basename} should not be committed to the repository`,
        recommendation: 'Remove this file from git tracking and add to .gitignore',
        autoFixable: true
      });
    }

    // Check if file should be in .gitignore
    if (this.shouldBeInGitignore(filename) && isTracked) {
      findings.push({
        type: 'missing_gitignore',
        name: 'File Should Be In .gitignore',
        severity: 'high',
        file: filename,
        description: `${basename} should be listed in .gitignore`,
        recommendation: `Add ${this.getGitignorePattern(filename)} to .gitignore`,
        autoFixable: true
      });
    }

    // Check configuration files for embedded secrets
    if (this.isConfigFile(filename)) {
      const configFindings = this.scanConfigFile(filename, content);
      findings.push(...configFindings);
    }

    // Check for backup files
    if (this.isBackupFile(filename)) {
      findings.push({
        type: 'backup_file',
        name: 'Backup File Found',
        severity: 'medium',
        file: filename,
        description: 'Backup files may contain sensitive data',
        recommendation: 'Remove backup files from repository and add pattern to .gitignore',
        autoFixable: true
      });
    }

    // Check file permissions concerns (in content)
    if (content.includes('chmod 777') || content.includes('0777')) {
      findings.push({
        type: 'insecure_permissions',
        name: 'Insecure File Permissions',
        severity: 'high',
        file: filename,
        description: 'chmod 777 grants full permissions to everyone',
        recommendation: 'Use restrictive permissions (e.g., 644 for files, 755 for directories)',
        autoFixable: false
      });
    }

    return findings;
  }

  /**
   * Check if file is sensitive
   * @param {string} filename - File path
   * @returns {boolean} True if sensitive
   */
  isSensitiveFile(filename) {
    const basename = path.basename(filename);
    
    return this.sensitiveFiles.some(pattern => {
      if (pattern.includes('*')) {
        const regex = new RegExp(pattern.replace(/\*/g, '.*'));
        return regex.test(basename);
      }
      return basename === pattern || filename.endsWith(pattern);
    });
  }

  /**
   * Check if file should be in .gitignore
   * @param {string} filename - File path
   * @returns {boolean} True if should be ignored
   */
  shouldBeInGitignore(filename) {
    const basename = path.basename(filename);
    
    return this.shouldBeIgnored.some(pattern => {
      if (pattern.includes('*')) {
        const regex = new RegExp(pattern.replace(/\*/g, '.*'));
        return regex.test(basename);
      }
      return basename === pattern || filename.endsWith(pattern);
    });
  }

  /**
   * Get appropriate .gitignore pattern for file
   * @param {string} filename - File path
   * @returns {string} Gitignore pattern
   */
  getGitignorePattern(filename) {
    const basename = path.basename(filename);
    
    // Return most appropriate pattern
    for (const pattern of this.shouldBeIgnored) {
      if (pattern.includes('*')) {
        const regex = new RegExp(pattern.replace(/\*/g, '.*'));
        if (regex.test(basename)) {
          return pattern;
        }
      } else if (basename === pattern) {
        return pattern;
      }
    }
    
    return basename;
  }

  /**
   * Check if file is a configuration file
   * @param {string} filename - File path
   * @returns {boolean} True if config file
   */
  isConfigFile(filename) {
    const basename = path.basename(filename);
    return this.configFiles.some(cf => basename === cf || filename.endsWith(cf));
  }

  /**
   * Scan configuration file for issues
   * @param {string} filename - File path
   * @param {string} content - File content
   * @returns {Array} Findings
   */
  scanConfigFile(filename, content) {
    const findings = [];

    // Check for embedded credentials in config
    const credentialPatterns = [
      /password\s*[:=]\s*['"]?[^'"\s]{8,}['"]?/gi,
      /api[_-]?key\s*[:=]\s*['"]?[^'"\s]{20,}['"]?/gi,
      /secret\s*[:=]\s*['"]?[^'"\s]{20,}['"]?/gi,
      /token\s*[:=]\s*['"]?[^'"\s]{20,}['"]?/gi
    ];

    for (const pattern of credentialPatterns) {
      if (pattern.test(content)) {
        findings.push({
          type: 'config_with_secrets',
          name: 'Configuration File Contains Credentials',
          severity: 'high',
          file: filename,
          description: 'Configuration file appears to contain embedded credentials',
          recommendation: 'Use environment variables or secure secret management',
          autoFixable: false
        });
        break;
      }
    }

    return findings;
  }

  /**
   * Check if file is a backup file
   * @param {string} filename - File path
   * @returns {boolean} True if backup file
   */
  isBackupFile(filename) {
    const backupExtensions = ['.bak', '.backup', '.old', '.orig', '~'];
    return backupExtensions.some(ext => filename.endsWith(ext));
  }

  /**
   * Scan directory structure for issues
   * @param {Array} files - List of file paths
   * @returns {Array} Findings
   */
  scanDirectory(files) {
    const findings = [];
    
    // Check for .git exposure in web directories
    if (files.some(f => f.startsWith('public/.git') || f.startsWith('www/.git'))) {
      findings.push({
        type: 'git_exposure',
        name: '.git Directory in Public Folder',
        severity: 'critical',
        description: '.git directory should not be in public web directories',
        recommendation: 'Move .git out of public directories or block access via web server config',
        autoFixable: false
      });
    }

    // Check for node_modules in repo
    const hasNodeModules = files.some(f => f.includes('node_modules/') && !f.includes('.gitignore'));
    if (hasNodeModules) {
      findings.push({
        type: 'dependency_folder',
        name: 'Dependencies Committed to Repository',
        severity: 'low',
        description: 'node_modules directory appears to be committed',
        recommendation: 'Add node_modules/ to .gitignore and remove from git',
        autoFixable: true
      });
    }

    return findings;
  }
}

module.exports = FileScanner;

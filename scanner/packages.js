/**
 * GitAntivirus - Package Scanner
 * Scans package.json for vulnerabilities and security issues
 */

class PackageScanner {
  constructor() {
    // Known vulnerable package patterns
    this.knownVulnerabilities = {
      'lodash': {
        vulnerable: ['<4.17.21'],
        cve: ['CVE-2020-8203', 'CVE-2019-10744'],
        severity: 'high',
        fixed: '4.17.21'
      },
      'axios': {
        vulnerable: ['<0.21.1'],
        cve: ['CVE-2020-28168'],
        severity: 'medium',
        fixed: '0.21.1'
      },
      'node-fetch': {
        vulnerable: ['<2.6.1'],
        cve: ['CVE-2020-15168'],
        severity: 'high',
        fixed: '2.6.1'
      },
      'minimist': {
        vulnerable: ['<1.2.6'],
        cve: ['CVE-2021-44906'],
        severity: 'critical',
        fixed: '1.2.6'
      },
      'ansi-regex': {
        vulnerable: ['<5.0.1'],
        cve: ['CVE-2021-3807'],
        severity: 'high',
        fixed: '5.0.1'
      },
      'trim-newlines': {
        vulnerable: ['<3.0.1'],
        cve: ['CVE-2021-33623'],
        severity: 'high',
        fixed: '3.0.1'
      },
      'glob-parent': {
        vulnerable: ['<5.1.2'],
        cve: ['CVE-2020-28469'],
        severity: 'high',
        fixed: '5.1.2'
      },
      'qs': {
        vulnerable: ['<6.5.3'],
        cve: ['CVE-2022-24999'],
        severity: 'high',
        fixed: '6.5.3'
      },
      'express': {
        vulnerable: ['<4.17.3'],
        cve: ['CVE-2022-24999'],
        severity: 'medium',
        fixed: '4.17.3'
      }
    };
  }

  /**
   * Scan package.json for vulnerabilities
   * @param {Object} packageJson - Parsed package.json content
   * @param {string} filename - Path to package.json
   * @returns {Array} Array of findings
   */
  scan(packageJson, filename = 'package.json') {
    const findings = [];

    if (!packageJson) {
      return findings;
    }

    // Check dependencies
    if (packageJson.dependencies) {
      const depFindings = this.scanDependencies(packageJson.dependencies, 'dependencies');
      findings.push(...depFindings);
    }

    // Check devDependencies
    if (packageJson.devDependencies) {
      const devDepFindings = this.scanDependencies(packageJson.devDependencies, 'devDependencies');
      findings.push(...devDepFindings);
    }

    // Check for missing security fields
    const securityFindings = this.checkSecurityConfig(packageJson);
    findings.push(...securityFindings);

    // Check for suspicious scripts
    const scriptFindings = this.scanScripts(packageJson.scripts);
    findings.push(...scriptFindings);

    // Add filename to all findings
    findings.forEach(finding => {
      finding.file = filename;
    });

    return findings;
  }

  /**
   * Scan dependencies for known vulnerabilities
   * @param {Object} dependencies - Dependencies object
   * @param {string} depType - Type of dependencies
   * @returns {Array} Findings
   */
  scanDependencies(dependencies, depType) {
    const findings = [];

    for (const [pkg, version] of Object.entries(dependencies)) {
      // Check against known vulnerabilities
      if (this.knownVulnerabilities[pkg]) {
        const vuln = this.knownVulnerabilities[pkg];
        const cleanVersion = version.replace(/[\^~><=]/g, '');
        
        if (this.isVulnerable(cleanVersion, vuln.vulnerable)) {
          findings.push({
            type: 'vulnerable_package',
            name: 'Vulnerable Package Detected',
            severity: vuln.severity,
            package: pkg,
            currentVersion: version,
            fixedVersion: vuln.fixed,
            cve: vuln.cve,
            depType,
            description: `${pkg}@${version} has known vulnerabilities: ${vuln.cve.join(', ')}`,
            recommendation: `Update to ${pkg}@${vuln.fixed} or later`,
            autoFixable: true
          });
        }
      }

      // Check for wildcards or very loose versioning
      if (version === '*' || version === 'latest') {
        findings.push({
          type: 'loose_versioning',
          name: 'Loose Version Constraint',
          severity: 'medium',
          package: pkg,
          currentVersion: version,
          depType,
          description: `Package ${pkg} uses loose version constraint "${version}"`,
          recommendation: 'Pin to specific version to ensure consistent builds',
          autoFixable: false
        });
      }

      // Check for deprecated packages
      if (this.isDeprecated(pkg)) {
        findings.push({
          type: 'deprecated_package',
          name: 'Deprecated Package',
          severity: 'low',
          package: pkg,
          currentVersion: version,
          depType,
          description: `${pkg} is deprecated`,
          recommendation: this.getAlternative(pkg),
          autoFixable: false
        });
      }
    }

    return findings;
  }

  /**
   * Check if version is vulnerable
   * @param {string} version - Version to check
   * @param {Array} vulnerableRanges - Array of vulnerable version ranges
   * @returns {boolean} True if vulnerable
   */
  isVulnerable(version, vulnerableRanges) {
    for (const range of vulnerableRanges) {
      if (range.startsWith('<')) {
        const maxVersion = range.substring(1);
        if (this.compareVersions(version, maxVersion) < 0) {
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Compare two semantic versions
   * @param {string} v1 - First version
   * @param {string} v2 - Second version
   * @returns {number} -1 if v1 < v2, 0 if equal, 1 if v1 > v2
   */
  compareVersions(v1, v2) {
    const parts1 = v1.split('.').map(Number);
    const parts2 = v2.split('.').map(Number);
    
    for (let i = 0; i < Math.max(parts1.length, parts2.length); i++) {
      const p1 = parts1[i] || 0;
      const p2 = parts2[i] || 0;
      
      if (p1 < p2) return -1;
      if (p1 > p2) return 1;
    }
    
    return 0;
  }

  /**
   * Check for deprecated packages
   * @param {string} pkg - Package name
   * @returns {boolean} True if deprecated
   */
  isDeprecated(pkg) {
    const deprecated = [
      'request',
      'node-uuid',
      'gulp-util',
      'bower'
    ];
    return deprecated.includes(pkg);
  }

  /**
   * Get alternative for deprecated package
   * @param {string} pkg - Package name
   * @returns {string} Recommendation
   */
  getAlternative(pkg) {
    const alternatives = {
      'request': 'Use axios, node-fetch, or got instead',
      'node-uuid': 'Use uuid package instead',
      'gulp-util': 'Use individual packages like fancy-log, plugin-error instead',
      'bower': 'Use npm or yarn for front-end dependencies'
    };
    return alternatives[pkg] || 'Find an actively maintained alternative';
  }

  /**
   * Check security configuration in package.json
   * @param {Object} packageJson - Package.json object
   * @returns {Array} Findings
   */
  checkSecurityConfig(packageJson) {
    const findings = [];

    // Check if private flag is set for internal packages
    if (!packageJson.private && !packageJson.name?.startsWith('@')) {
      findings.push({
        type: 'missing_private_flag',
        name: 'Missing Private Flag',
        severity: 'low',
        description: 'Consider setting "private": true if this package should not be published',
        recommendation: 'Add "private": true to package.json if not publishing to npm',
        autoFixable: true
      });
    }

    // Check for engines specification
    if (!packageJson.engines) {
      findings.push({
        type: 'missing_engines',
        name: 'Missing Node Version Specification',
        severity: 'low',
        description: 'No Node.js version specified in engines field',
        recommendation: 'Specify required Node.js version in "engines" field',
        autoFixable: false
      });
    }

    return findings;
  }

  /**
   * Scan npm scripts for suspicious commands
   * @param {Object} scripts - Scripts object from package.json
   * @returns {Array} Findings
   */
  scanScripts(scripts) {
    const findings = [];

    if (!scripts) {
      return findings;
    }

    const suspiciousPatterns = [
      { pattern: /curl.*\|.*sh/, name: 'Piping curl to shell', severity: 'critical' },
      { pattern: /wget.*\|.*sh/, name: 'Piping wget to shell', severity: 'critical' },
      { pattern: /eval\s*\(/, name: 'Using eval()', severity: 'high' },
      { pattern: /rm\s+-rf\s+\//, name: 'Dangerous rm command', severity: 'critical' },
      { pattern: /chmod\s+777/, name: 'Overly permissive chmod', severity: 'high' },
      { pattern: />\s*\/dev\/null\s+2>&1/, name: 'Silencing errors', severity: 'medium' }
    ];

    for (const [scriptName, command] of Object.entries(scripts)) {
      for (const { pattern, name, severity } of suspiciousPatterns) {
        if (pattern.test(command)) {
          findings.push({
            type: 'suspicious_script',
            name: 'Suspicious Script Command',
            severity,
            script: scriptName,
            description: `Script "${scriptName}" contains: ${name}`,
            command: command.length > 100 ? command.substring(0, 100) + '...' : command,
            recommendation: 'Review this script for security implications',
            autoFixable: false
          });
        }
      }
    }

    return findings;
  }

  /**
   * Generate auto-fix for vulnerable dependencies
   * @param {Object} packageJson - Package.json object
   * @param {Array} findings - Vulnerability findings
   * @returns {Object} Updated package.json
   */
  generateFix(packageJson, findings) {
    const fixed = JSON.parse(JSON.stringify(packageJson));

    for (const finding of findings) {
      if (finding.type === 'vulnerable_package' && finding.autoFixable) {
        const { package: pkg, fixedVersion, depType } = finding;
        
        if (fixed[depType] && fixed[depType][pkg]) {
          // Update to fixed version, preserving prefix if any
          const currentVersion = fixed[depType][pkg];
          const prefix = currentVersion.match(/^[\^~]/)?.[0] || '';
          fixed[depType][pkg] = prefix + fixedVersion;
        }
      }
    }

    return fixed;
  }
}

module.exports = PackageScanner;

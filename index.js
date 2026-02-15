/**
 * GitAntivirus - Main Entry Point
 * Automated security scanning service for GitHub repositories
 */

const SecretScanner = require('./scanner/secrets');
const FileScanner = require('./scanner/files');
const PackageScanner = require('./scanner/packages');
const CodeScanner = require('./scanner/code');
const AutoFix = require('./fixes/autofix');
const ReportGenerator = require('./reporters/markdown');

class GitAntivirus {
  constructor(options = {}) {
    this.options = {
      scanSecrets: true,
      scanFiles: true,
      scanPackages: true,
      scanCode: true,
      autoFix: false,
      generateReport: true,
      ...options
    };

    // Initialize scanners
    this.secretScanner = new SecretScanner();
    this.fileScanner = new FileScanner();
    this.packageScanner = new PackageScanner();
    this.codeScanner = new CodeScanner();
    this.autoFix = new AutoFix();
    this.reportGenerator = new ReportGenerator();

    this.findings = [];
  }

  /**
   * Scan a repository
   * @param {string} repoPath - Path to repository
   * @returns {Promise<Object>} Scan results
   */
  async scanRepository(repoPath) {
    console.log('🔍 Starting GitAntivirus scan...\n');
    
    this.findings = [];
    const fs = require('fs');
    const path = require('path');

    try {
      // Get list of files
      const files = this.getAllFiles(repoPath);
      console.log(`📁 Found ${files.length} files to scan\n`);

      // Scan each file
      for (const file of files) {
        const relativePath = path.relative(repoPath, file);
        
        // Skip certain directories
        if (this.shouldSkip(relativePath)) {
          continue;
        }

        try {
          const content = fs.readFileSync(file, 'utf8');
          await this.scanFile(relativePath, content);
        } catch (error) {
          // Skip binary files or files that can't be read
          continue;
        }
      }

      // Scan directory structure
      if (this.options.scanFiles) {
        const relativeFiles = files.map(f => path.relative(repoPath, f));
        const dirFindings = this.fileScanner.scanDirectory(relativeFiles);
        this.findings.push(...dirFindings);
      }

      console.log(`\n✅ Scan complete! Found ${this.findings.length} issue(s)\n`);

      // Generate report
      let report = null;
      if (this.options.generateReport) {
        report = this.reportGenerator.generateMarkdown(this.findings, {
          repoName: path.basename(repoPath),
          timestamp: new Date()
        });
      }

      // Apply auto-fixes if enabled
      let fixResults = null;
      if (this.options.autoFix && this.findings.some(f => f.autoFixable)) {
        console.log('🤖 Applying auto-fixes...\n');
        fixResults = this.autoFix.applyFixes(this.findings, repoPath);
        console.log(`✅ Fixed ${fixResults.fixed.length} file(s)\n`);
      }

      return {
        findings: this.findings,
        report,
        fixResults,
        stats: this.reportGenerator.calculateStats(this.findings)
      };

    } catch (error) {
      console.error('❌ Error during scan:', error);
      throw error;
    }
  }

  /**
   * Scan a single file
   * @param {string} filename - Relative file path
   * @param {string} content - File content
   */
  async scanFile(filename, content) {
    // Scan for secrets
    if (this.options.scanSecrets) {
      const secretFindings = this.secretScanner.scan(content, filename);
      this.findings.push(...secretFindings);
    }

    // Scan file properties
    if (this.options.scanFiles) {
      const fileFindings = this.fileScanner.scan(filename, content, true);
      this.findings.push(...fileFindings);
    }

    // Scan package.json
    if (this.options.scanPackages && filename.endsWith('package.json')) {
      try {
        const packageJson = JSON.parse(content);
        const packageFindings = this.packageScanner.scan(packageJson, filename);
        this.findings.push(...packageFindings);
      } catch (error) {
        // Invalid JSON, will be caught by code scanner
      }
    }

    // Scan code
    if (this.options.scanCode) {
      if (filename.endsWith('.js') || filename.endsWith('.jsx') || 
          filename.endsWith('.ts') || filename.endsWith('.tsx')) {
        const codeFindings = this.codeScanner.scan(content, filename);
        this.findings.push(...codeFindings);
      } else if (filename.endsWith('.json') && !filename.endsWith('package.json')) {
        const jsonFindings = this.codeScanner.scanJSON(content, filename);
        this.findings.push(...jsonFindings);
      }
    }
  }

  /**
   * Get all files in directory recursively
   * @param {string} dir - Directory path
   * @param {Array} fileList - Accumulated file list
   * @returns {Array} List of files
   */
  getAllFiles(dir, fileList = []) {
    const fs = require('fs');
    const path = require('path');

    try {
      const files = fs.readdirSync(dir);

      files.forEach(file => {
        const filePath = path.join(dir, file);
        
        try {
          const stat = fs.statSync(filePath);
          
          if (stat.isDirectory()) {
            // Skip .git directory
            if (file !== '.git') {
              this.getAllFiles(filePath, fileList);
            }
          } else {
            fileList.push(filePath);
          }
        } catch (error) {
          // Skip files we can't access
        }
      });
    } catch (error) {
      // Skip directories we can't read
    }

    return fileList;
  }

  /**
   * Check if file should be skipped
   * @param {string} filename - File path
   * @returns {boolean} True if should skip
   */
  shouldSkip(filename) {
    const skipPatterns = [
      /node_modules\//,
      /\.git\//,
      /dist\//,
      /build\//,
      /coverage\//,
      /\.min\.js$/,
      /\.map$/,
      /package-lock\.json$/,
      /yarn\.lock$/
    ];

    return skipPatterns.some(pattern => pattern.test(filename));
  }

  /**
   * Get findings
   * @returns {Array} All findings
   */
  getFindings() {
    return this.findings;
  }

  /**
   * Get findings by severity
   * @param {string} severity - Severity level
   * @returns {Array} Filtered findings
   */
  getFindingsBySeverity(severity) {
    return this.findings.filter(f => f.severity === severity);
  }

  /**
   * Get auto-fixable findings
   * @returns {Array} Auto-fixable findings
   */
  getAutoFixableFindings() {
    return this.findings.filter(f => f.autoFixable);
  }
}

module.exports = GitAntivirus;

// CLI usage
if (require.main === module) {
  const path = require('path');
  const fs = require('fs');
  
  const repoPath = process.argv[2] || process.cwd();
  const autoFix = process.argv.includes('--fix');
  
  console.log(`
╔════════════════════════════════════════╗
║        🛡️  GitAntivirus v1.0.0        ║
║    Automated Security Scanner          ║
╚════════════════════════════════════════╝
`);

  const scanner = new GitAntivirus({
    autoFix: autoFix
  });

  scanner.scanRepository(repoPath)
    .then(results => {
      // Save report
      if (results.report) {
        const reportPath = path.join(repoPath, 'SECURITY_REPORT.md');
        fs.writeFileSync(reportPath, results.report);
        console.log(`📄 Report saved to: ${reportPath}\n`);
      }

      // Display summary
      console.log('📊 Summary:');
      console.log(`   Critical: ${results.stats.critical}`);
      console.log(`   High: ${results.stats.high}`);
      console.log(`   Medium: ${results.stats.medium}`);
      console.log(`   Low: ${results.stats.low}`);
      console.log(`   Info: ${results.stats.info}`);
      console.log(`\n   Total Issues: ${results.stats.total}`);
      
      if (results.stats.autoFixable > 0) {
        console.log(`\n   🤖 Auto-fixable: ${results.stats.autoFixable}`);
        if (!autoFix) {
          console.log(`   Run with --fix to apply automatic fixes`);
        }
      }

      // Exit with error code if critical or high issues found
      if (results.stats.critical > 0 || results.stats.high > 0) {
        process.exit(1);
      }
    })
    .catch(error => {
      console.error('❌ Scan failed:', error);
      process.exit(1);
    });
}

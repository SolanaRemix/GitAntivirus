/**
 * GitAntivirus - Auto-Fix Module
 * Automatically fixes common security issues
 */

const fs = require('fs');
const path = require('path');

class AutoFix {
  constructor() {
    this.fixedFiles = [];
  }

  /**
   * Apply auto-fixes to findings
   * @param {Array} findings - Security findings
   * @param {string} repoPath - Repository path
   * @returns {Object} Fix results
   */
  applyFixes(findings, repoPath) {
    const results = {
      fixed: [],
      skipped: [],
      errors: []
    };

    // Group findings by file
    const fileGroups = this.groupByFile(findings);

    for (const [filename, fileFindings] of Object.entries(fileGroups)) {
      try {
        const fixable = fileFindings.filter(f => f.autoFixable);
        
        if (fixable.length === 0) {
          results.skipped.push({
            file: filename,
            reason: 'No auto-fixable issues'
          });
          continue;
        }

        const fixResult = this.fixFile(filename, fixable, repoPath);
        
        if (fixResult.success) {
          results.fixed.push({
            file: filename,
            fixes: fixResult.fixes
          });
        } else {
          results.errors.push({
            file: filename,
            error: fixResult.error
          });
        }
      } catch (error) {
        results.errors.push({
          file: filename,
          error: error.message
        });
      }
    }

    return results;
  }

  /**
   * Group findings by file
   * @param {Array} findings - All findings
   * @returns {Object} Findings grouped by file
   */
  groupByFile(findings) {
    const groups = {};
    
    for (const finding of findings) {
      if (!finding.file) continue;
      
      if (!groups[finding.file]) {
        groups[finding.file] = [];
      }
      groups[finding.file].push(finding);
    }
    
    return groups;
  }

  /**
   * Fix issues in a single file
   * @param {string} filename - File to fix
   * @param {Array} findings - Findings for this file
   * @param {string} repoPath - Repository path
   * @returns {Object} Fix result
   */
  fixFile(filename, findings, repoPath) {
    const filePath = path.join(repoPath, filename);
    const fixes = [];

    try {
      let content = fs.readFileSync(filePath, 'utf8');
      let modified = false;

      for (const finding of findings) {
        const fixMethod = this.getFixMethod(finding.type);
        
        if (fixMethod) {
          const result = fixMethod.call(this, content, finding, repoPath);
          
          if (result.modified) {
            content = result.content;
            modified = true;
            fixes.push({
              type: finding.type,
              description: result.description
            });
          }
        }
      }

      if (modified) {
        fs.writeFileSync(filePath, content, 'utf8');
        this.fixedFiles.push(filename);
      }

      return {
        success: true,
        fixes
      };
    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Get fix method for finding type
   * @param {string} type - Finding type
   * @returns {Function} Fix function
   */
  getFixMethod(type) {
    const methods = {
      'sensitive_file': this.fixSensitiveFile,
      'missing_gitignore': this.fixMissingGitignore,
      'backup_file': this.fixBackupFile,
      'vulnerable_package': this.fixVulnerablePackage,
      'console_log': this.fixConsoleLog,
      'debugger': this.fixDebugger,
      'missing_private_flag': this.fixPrivateFlag,
      'dependency_folder': this.fixDependencyFolder
    };
    
    return methods[type];
  }

  /**
   * Fix sensitive file issue by removing from git
   * @param {string} content - File content
   * @param {Object} finding - Finding details
   * @param {string} repoPath - Repository path
   * @returns {Object} Result
   */
  fixSensitiveFile(content, finding, repoPath) {
    // Add to .gitignore and remove from git
    const gitignorePath = path.join(repoPath, '.gitignore');
    const pattern = path.basename(finding.file);
    
    this.addToGitignore(gitignorePath, pattern);
    
    return {
      modified: false, // Don't modify the file content
      description: `Added ${pattern} to .gitignore`
    };
  }

  /**
   * Fix missing .gitignore entry
   * @param {string} content - File content
   * @param {Object} finding - Finding details
   * @param {string} repoPath - Repository path
   * @returns {Object} Result
   */
  fixMissingGitignore(content, finding, repoPath) {
    const gitignorePath = path.join(repoPath, '.gitignore');
    const pattern = finding.recommendation.match(/Add (.+) to/)?.[1] || path.basename(finding.file);
    
    this.addToGitignore(gitignorePath, pattern);
    
    return {
      modified: false,
      description: `Added ${pattern} to .gitignore`
    };
  }

  /**
   * Add pattern to .gitignore
   * @param {string} gitignorePath - Path to .gitignore
   * @param {string} pattern - Pattern to add
   */
  addToGitignore(gitignorePath, pattern) {
    let content = '';
    
    if (fs.existsSync(gitignorePath)) {
      content = fs.readFileSync(gitignorePath, 'utf8');
    }
    
    // Check if pattern already exists
    const lines = content.split('\n');
    if (lines.some(line => line.trim() === pattern)) {
      return; // Already exists
    }
    
    // Add pattern
    if (content && !content.endsWith('\n')) {
      content += '\n';
    }
    
    content += `${pattern}\n`;
    
    fs.writeFileSync(gitignorePath, content, 'utf8');
  }

  /**
   * Fix backup file by removing it
   * @param {string} content - File content
   * @param {Object} finding - Finding details
   * @param {string} repoPath - Repository path
   * @returns {Object} Result
   */
  fixBackupFile(content, finding, repoPath) {
    const filePath = path.join(repoPath, finding.file);
    
    try {
      fs.unlinkSync(filePath);
      return {
        modified: false,
        description: 'Removed backup file'
      };
    } catch (error) {
      return {
        modified: false,
        description: `Could not remove backup file: ${error.message}`
      };
    }
  }

  /**
   * Fix vulnerable package in package.json
   * @param {string} content - package.json content
   * @param {Object} finding - Finding details
   * @returns {Object} Result
   */
  fixVulnerablePackage(content, finding) {
    try {
      const pkg = JSON.parse(content);
      const { package: pkgName, fixedVersion, depType } = finding;
      
      if (pkg[depType] && pkg[depType][pkgName]) {
        const currentVersion = pkg[depType][pkgName];
        const prefix = currentVersion.match(/^[\^~]/)?.[0] || '';
        pkg[depType][pkgName] = prefix + fixedVersion;
        
        return {
          modified: true,
          content: JSON.stringify(pkg, null, 2) + '\n',
          description: `Updated ${pkgName} from ${currentVersion} to ${prefix}${fixedVersion}`
        };
      }
    } catch (error) {
      return {
        modified: false,
        description: `Error updating package: ${error.message}`
      };
    }
    
    return {
      modified: false,
      description: 'Package not found or already fixed'
    };
  }

  /**
   * Remove console.log statements
   * @param {string} content - File content
   * @param {Object} finding - Finding details
   * @returns {Object} Result
   */
  fixConsoleLog(content, finding) {
    // Remove console statements (simple approach - remove entire line)
    const lines = content.split('\n');
    const lineIndex = finding.line - 1;
    
    if (lineIndex >= 0 && lineIndex < lines.length) {
      // Only remove if the line is just a console statement
      if (lines[lineIndex].trim().startsWith('console.')) {
        lines.splice(lineIndex, 1);
        
        return {
          modified: true,
          content: lines.join('\n'),
          description: 'Removed console statement'
        };
      }
    }
    
    return {
      modified: false,
      description: 'Could not safely remove console statement'
    };
  }

  /**
   * Remove debugger statements
   * @param {string} content - File content
   * @param {Object} finding - Finding details
   * @returns {Object} Result
   */
  fixDebugger(content, finding) {
    const lines = content.split('\n');
    const lineIndex = finding.line - 1;
    
    if (lineIndex >= 0 && lineIndex < lines.length) {
      if (lines[lineIndex].includes('debugger')) {
        lines[lineIndex] = lines[lineIndex].replace(/debugger;?/g, '');
        
        // Remove line if it's now empty
        if (lines[lineIndex].trim() === '') {
          lines.splice(lineIndex, 1);
        }
        
        return {
          modified: true,
          content: lines.join('\n'),
          description: 'Removed debugger statement'
        };
      }
    }
    
    return {
      modified: false,
      description: 'Could not remove debugger statement'
    };
  }

  /**
   * Add private flag to package.json
   * @param {string} content - package.json content
   * @returns {Object} Result
   */
  fixPrivateFlag(content) {
    try {
      const pkg = JSON.parse(content);
      pkg.private = true;
      
      return {
        modified: true,
        content: JSON.stringify(pkg, null, 2) + '\n',
        description: 'Added "private": true to package.json'
      };
    } catch (error) {
      return {
        modified: false,
        description: `Error adding private flag: ${error.message}`
      };
    }
  }

  /**
   * Fix dependency folder issue
   * @param {string} content - File content
   * @param {Object} finding - Finding details
   * @param {string} repoPath - Repository path
   * @returns {Object} Result
   */
  fixDependencyFolder(content, finding, repoPath) {
    const gitignorePath = path.join(repoPath, '.gitignore');
    this.addToGitignore(gitignorePath, 'node_modules/');
    
    return {
      modified: false,
      description: 'Added node_modules/ to .gitignore'
    };
  }
}

module.exports = AutoFix;

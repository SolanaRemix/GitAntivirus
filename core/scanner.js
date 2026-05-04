/**
 * GitAntivirus - Core Scanner
 * Walks the project tree and applies detection rules to every file
 */

const fs = require('fs');
const path = require('path');
const { rules } = require('./rules');
const { calculateRisk } = require('./risk');

/** Directories to always skip */
const SKIP_DIRS = new Set(['.git', 'node_modules', 'dist', 'build', 'coverage', 'tests/malicious']);

/** File extensions we can meaningfully scan as text */
const TEXT_EXTENSIONS = new Set([
  '.js', '.jsx', '.ts', '.tsx', '.mjs', '.cjs',
  '.json', '.yml', '.yaml', '.env', '.sh',
  '.php', '.py', '.rb', '.go', '.sol',
  '.txt', '.md', '.html', '.htm', '.xml', '.csv'
]);

/**
 * Read ignore patterns from .gitantivirusignore in cwd (if present)
 * Each non-empty, non-comment line is treated as a path prefix to skip.
 * @returns {string[]}
 */
function readIgnorePatterns() {
  const ignorePath = path.join(process.cwd(), '.gitantivirusignore');
  if (!fs.existsSync(ignorePath)) return [];
  return fs.readFileSync(ignorePath, 'utf8')
    .split('\n')
    .map(l => l.trim())
    .filter(l => l && !l.startsWith('#'));
}

/**
 * Check whether a path (relative to cwd) should be skipped
 * @param {string} relPath - path relative to process.cwd()
 * @param {string[]} ignorePatterns
 * @returns {boolean}
 */
function shouldSkip(relPath, ignorePatterns) {
  const parts = relPath.split(path.sep);
  // Skip if any directory component is in SKIP_DIRS
  for (const part of parts) {
    if (SKIP_DIRS.has(part)) return true;
  }
  // Respect .gitantivirusignore patterns
  for (const pattern of ignorePatterns) {
    if (relPath.startsWith(pattern) || relPath === pattern) return true;
  }
  return false;
}

/**
 * Recursively collect all scannable file paths under dir
 * @param {string} dir
 * @param {string[]} ignorePatterns
 * @param {string[]} [fileList]
 * @returns {string[]}
 */
function walk(dir, ignorePatterns, fileList = []) {
  let entries;
  try {
    entries = fs.readdirSync(dir);
  } catch (_) {
    return fileList;
  }

  for (const entry of entries) {
    const fullPath = path.join(dir, entry);
    const relPath = path.relative(process.cwd(), fullPath);

    if (shouldSkip(relPath, ignorePatterns)) continue;

    let stat;
    try {
      stat = fs.statSync(fullPath);
    } catch (_) {
      continue;
    }

    if (stat.isDirectory()) {
      walk(fullPath, ignorePatterns, fileList);
    } else if (TEXT_EXTENSIONS.has(path.extname(entry).toLowerCase())) {
      fileList.push(fullPath);
    }
  }
  return fileList;
}

/**
 * Scan a single file against all rules
 * @param {string} filePath
 * @returns {Array} findings
 */
function scanFile(filePath) {
  let content;
  try {
    content = fs.readFileSync(filePath, 'utf8');
  } catch (_) {
    return [];
  }

  const findings = [];
  for (const rule of rules) {
    if (rule.pattern.test(content)) {
      findings.push({
        type: rule.name,
        severity: rule.severity,
        file: filePath
      });
    }
  }
  return findings;
}

/**
 * Scan all files under process.cwd()
 * @returns {Promise<{ findings: Array, score: number, level: string }>}
 */
async function scanProject() {
  const ignorePatterns = readIgnorePatterns();
  const files = walk(process.cwd(), ignorePatterns);
  const findings = files.flatMap(f => scanFile(f));
  const risk = calculateRisk(findings);
  return { findings, score: risk.score, level: risk.level };
}

module.exports = { scanProject };

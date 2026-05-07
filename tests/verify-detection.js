/**
 * GitAntivirus — Detection Verification Tests
 *
 * Verifies that the scanner correctly detects malicious patterns in the
 * test fixtures under tests/malicious/ and passes on safe files.
 *
 * Exit codes:
 *   0 — all assertions passed
 *   1 — one or more assertions failed
 */

'use strict';

const path = require('path');
const fs = require('fs');
const os = require('os');
const { rules } = require('../core/rules');
const { calculateRisk } = require('../core/risk');
const { scanProject } = require('../core/scanner');

let passed = 0;
let failed = 0;

function assert(condition, message) {
  if (condition) {
    console.log(`  ✅ PASS: ${message}`);
    passed++;
  } else {
    console.error(`  ❌ FAIL: ${message}`);
    failed++;
  }
}

/**
 * Scan a single file's content against all rules (inline, no disk skipping)
 */
function scanContent(content) {
  const findings = [];
  for (const rule of rules) {
    if (rule.pattern.test(content)) {
      findings.push({ type: rule.name, severity: rule.severity });
    }
  }
  return findings;
}

// --- Test 1: malicious private key is detected ---
console.log('\n[Test 1] tests/malicious/key.js must trigger a critical finding');
const maliciousKeyPath = path.join(__dirname, 'malicious', 'key.js');
const maliciousContent = fs.readFileSync(maliciousKeyPath, 'utf8');
const maliciousFindings = scanContent(maliciousContent);
const maliciousRisk = calculateRisk(maliciousFindings);

assert(maliciousFindings.length > 0, 'Scanner found at least one issue in key.js');
assert(
  maliciousFindings.some(f => f.severity === 'critical'),
  'At least one finding has critical severity'
);
assert(maliciousRisk.level === 'critical', `Risk level is "critical" (got "${maliciousRisk.level}")`);

// --- Test 2: safe file produces no findings ---
console.log('\n[Test 2] tests/safe/clean.js must produce zero findings');
const safeCleanPath = path.join(__dirname, 'safe', 'clean.js');
const safeContent = fs.readFileSync(safeCleanPath, 'utf8');
const safeFindings = scanContent(safeContent);

assert(safeFindings.length === 0, `No findings in clean.js (got ${safeFindings.length})`);

// --- Test 3: risk engine returns expected levels ---
console.log('\n[Test 3] Risk engine returns correct levels');
const { level: lowLevel } = calculateRisk([{ severity: 'low' }]);
assert(lowLevel === 'low', `score 10 → "low" (got "${lowLevel}")`);

const { level: medLevel } = calculateRisk([{ severity: 'medium' }, { severity: 'medium' }]);
assert(medLevel === 'medium', `score 50 → "medium" (got "${medLevel}")`);

const { level: highLevel } = calculateRisk([{ severity: 'high' }, { severity: 'medium' }]);
assert(highLevel === 'high', `score 75 → "high" (got "${highLevel}")`);

const { level: critLevel } = calculateRisk([{ severity: 'critical' }]);
assert(critLevel === 'critical', `score 90 → "critical" (got "${critLevel}")`);

// --- Test 4: scanProject() integration — walk, ignore, and hard-skip ---
console.log('\n[Test 4] scanProject() integration: walking, .gitantivirusignore, and hard-skip');

(async () => {
  const originalCwd = process.cwd();
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gitav-test-'));

  try {
    // Build the test fixture key in two parts so the scanner doesn't flag *this* source file.
    // The concatenated string is '0x' followed by exactly 64 hex chars, which triggers the
    // Private Key Exposure detection rule.
    const fakeKey = '0x123456789abcdef123456789' +
                    'abcdef123456789abcdef123456789abcdef1234';
    const badContent = `const key = '${fakeKey}';`;

    // Write a malicious file that should be found (matches Private Key Exposure rule: 0x + 64 hex chars)
    fs.mkdirSync(path.join(tmpDir, 'src'), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, 'src', 'bad.js'), badContent);

    // Write a safe file
    fs.writeFileSync(
      path.join(tmpDir, 'src', 'good.js'),
      'console.log("hello world");'
    );

    // Write a file in a hard-skipped subtree (tests/malicious)
    fs.mkdirSync(path.join(tmpDir, 'tests', 'malicious'), { recursive: true });
    fs.writeFileSync(path.join(tmpDir, 'tests', 'malicious', 'fixture.js'), badContent);

    // Write an ignored file via .gitantivirusignore
    fs.mkdirSync(path.join(tmpDir, 'ignored'), { recursive: true });
    fs.writeFileSync(
      path.join(tmpDir, 'ignored', 'secret.js'),
      'const key = "abcdef1234567890abcdef1234567890abcdef1234567890abcdef1234567890";'
    );
    fs.writeFileSync(
      path.join(tmpDir, '.gitantivirusignore'),
      'ignored/\n'
    );

    process.chdir(tmpDir);
    const result = await scanProject();

    // Should find the malicious key in src/bad.js
    assert(result.findings.length > 0, 'scanProject() detected findings in src/bad.js');

    // All finding paths must be relative (no absolute paths)
    const hasAbsPath = result.findings.some(f => path.isAbsolute(f.file));
    assert(!hasAbsPath, 'All finding paths are relative (not absolute)');

    // The hard-skipped tests/malicious/ subtree must not appear in findings.
    // Normalise separators so the check is platform-independent.
    const maliciousPrefix = path.join('tests', 'malicious');
    const hasSkippedPath = result.findings.some(
      f => f.file === maliciousPrefix || f.file.startsWith(maliciousPrefix + path.sep)
    );
    assert(!hasSkippedPath, 'tests/malicious/ subtree is hard-skipped by scanProject()');

    // The .gitantivirusignore'd directory must not appear in findings
    const hasIgnoredPath = result.findings.some(
      f => f.file === 'ignored' || f.file.startsWith('ignored' + path.sep)
    );
    assert(!hasIgnoredPath, '.gitantivirusignore exclusion is respected by scanProject()');

  } finally {
    process.chdir(originalCwd);
    fs.rmSync(tmpDir, { recursive: true, force: true });
  }

  // --- Summary ---
  console.log(`\n📊 Results: ${passed} passed, ${failed} failed\n`);
  if (failed > 0) {
    process.exit(1);
  }
  process.exit(0);
})();

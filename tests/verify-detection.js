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
const { rules } = require('../core/rules');
const { calculateRisk } = require('../core/risk');

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

// --- Summary ---
console.log(`\n📊 Results: ${passed} passed, ${failed} failed\n`);
if (failed > 0) {
  process.exit(1);
}
process.exit(0);

#!/usr/bin/env node
/**
 * GitAntivirus CLI  –  gitav
 *
 * Commands
 *   gitav scan [--fail-on=<level>]   Run a full project scan
 *   gitav report                      Print the last scan report (reports/latest.json)
 *   gitav fix                         (stub) Apply auto-fixes
 *   gitav watch                       (stub) Real-time watcher
 *
 * Exit codes
 *   0  scan passed
 *   1  scan failed (risk level >= fail-on threshold)
 */

'use strict';

const { scanProject } = require('../core/scanner');
const { generateReport } = require('../core/reporter');

const LEVELS = ['low', 'medium', 'high', 'critical'];

const args = process.argv.slice(2);
const command = args[0];

/**
 * Parse --flag=value or --flag value style arguments
 * @param {string} flag
 * @returns {string|null}
 */
function getArg(flag) {
  for (let i = 0; i < args.length; i++) {
    if (args[i].startsWith(`${flag}=`)) {
      return args[i].split('=').slice(1).join('=');
    }
    if (args[i] === flag && i + 1 < args.length) {
      return args[i + 1];
    }
  }
  return null;
}

(async () => {
  if (command === 'scan') {
    const failOn = (getArg('--fail-on') || 'high').toLowerCase();

    if (!LEVELS.includes(failOn)) {
      console.error(`❌ Invalid --fail-on level: "${failOn}". Choose from: ${LEVELS.join(', ')}`);
      process.exit(1);
    }

    console.log('🔍 GitAntivirus — running scan…\n');

    let result;
    try {
      result = await scanProject();
    } catch (err) {
      console.error('❌ Scan error:', err.message);
      process.exit(1);
    }

    generateReport(result);

    console.log(`📊 Findings   : ${result.findings.length}`);
    console.log(`📈 Risk Score : ${result.score}/100`);
    console.log(`🔖 Risk Level : ${result.level.toUpperCase()}`);

    if (result.findings.length > 0) {
      console.log('\n⚠️  Detections:');
      for (const f of result.findings) {
        console.log(`   [${f.severity.toUpperCase()}] ${f.type} — ${f.file}`);
      }
    }

    const failIndex = LEVELS.indexOf(failOn);
    const resultIndex = LEVELS.indexOf(result.level);

    if (resultIndex >= failIndex) {
      console.error(`\n❌ Scan FAILED — risk level "${result.level}" meets or exceeds threshold "${failOn}"`);
      process.exit(1);
    }

    console.log('\n✅ Scan PASSED');
    process.exit(0);

  } else if (command === 'fix') {
    console.log('🔧 gitav fix — not yet implemented');
    process.exit(0);

  } else if (command === 'report') {
    const path = require('path');
    const fs = require('fs');
    const reportPath = path.join(process.cwd(), 'reports', 'latest.json');
    if (!fs.existsSync(reportPath)) {
      console.error('❌ No report found. Run `gitav scan` first.');
      process.exit(1);
    }
    console.log(fs.readFileSync(reportPath, 'utf8'));
    process.exit(0);

  } else if (command === 'watch') {
    console.log('👁️  gitav watch — not yet implemented');
    process.exit(0);

  } else {
    console.log('Usage:');
    console.log('  gitav scan [--fail-on=low|medium|high|critical]');
    console.log('  gitav fix');
    console.log('  gitav report');
    console.log('  gitav watch');
    process.exit(1);
  }
})();

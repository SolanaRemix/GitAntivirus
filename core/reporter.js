/**
 * GitAntivirus - Report Generator
 * Writes JSON scan reports to the reports/ directory
 */

const fs = require('fs');
const path = require('path');

/**
 * Persist scan results to reports/latest.json
 * @param {Object} result - Result object from scanProject()
 */
function generateReport(result) {
  const reportsDir = path.join(process.cwd(), 'reports');
  if (!fs.existsSync(reportsDir)) {
    fs.mkdirSync(reportsDir, { recursive: true });
  }
  fs.writeFileSync(
    path.join(reportsDir, 'latest.json'),
    JSON.stringify({ ...result, timestamp: new Date().toISOString() }, null, 2)
  );
}

module.exports = { generateReport };

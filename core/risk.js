/**
 * GitAntivirus - Risk Engine
 * Calculates a composite risk score from scan findings
 *
 * Scoring bands:
 *   LOW      0–30
 *   MEDIUM  31–60
 *   HIGH    61–85
 *   CRITICAL 86–100 → pipeline blocked
 */

const WEIGHTS = {
  critical: 90,
  high: 50,
  medium: 25,
  low: 10,
  info: 2
};

/**
 * Calculate risk level and score from an array of findings
 * @param {Array} findings
 * @returns {{ score: number, level: string }}
 */
function calculateRisk(findings) {
  let score = findings.reduce((acc, f) => acc + (WEIGHTS[f.severity] || 0), 0);
  if (score > 100) score = 100;

  let level = 'low';
  if (score > 30) level = 'medium';
  if (score > 60) level = 'high';
  if (score > 85) level = 'critical';

  return { score, level };
}

module.exports = { calculateRisk };

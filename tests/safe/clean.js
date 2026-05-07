/**
 * SAFE TEST FILE — no secrets, no dangerous patterns
 *
 * The GitAntivirus scanner MUST pass this file cleanly.
 */

function add(a, b) {
  return a + b;
}

function greet(name) {
  return `Hello, ${name}!`;
}

module.exports = { add, greet };

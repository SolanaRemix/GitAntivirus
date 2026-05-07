/**
 * MALICIOUS TEST FILE — fake private key
 *
 * This file is intentionally crafted to trigger the GitAntivirus scanner.
 * It MUST cause a "critical" finding and fail the pipeline.
 * DO NOT use this key for any real purpose — it is a test fixture only.
 */

// Simulated exposed Ethereum private key (64 hex chars after 0x)
const PRIVATE_KEY = '0x123456789abcdef123456789abcdef123456789abcdef123456789abcdef1234';

module.exports = { PRIVATE_KEY };

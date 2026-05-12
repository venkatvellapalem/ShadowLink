/**
 * scoring.js — ShadowLink Phishing Detection
 *
 * Maps a cumulative numeric risk score to a human-readable threat level.
 *
 * Score composition reference (approximate weights):
 *   +60  Homoglyph / look-alike domain attack (per brand match)
 *   +30  Raw IP address URL
 *   +25  IDN / Punycode domain
 *   +20  Suspicious TLD
 *   +20  Login form on untrusted domain (per loginDetector hit)
 *   +15  HTTP (no encryption)
 *   +15  Excessive subdomain depth
 *   +10  Suspicious keyword in domain (per keyword)
 *   +10  Unusually long URL
 *   +10  Open-redirect query parameter
 */

// ---------------------------------------------------------------------------
// classifyThreat(score)
//
// @param  {number} score — Accumulated risk score from the threat engine
// @returns {string}       — One of: 'Safe' | 'Warning' | 'Suspicious' | 'Dangerous'
//
// Threshold rationale:
//   ≥ 100  Dangerous  — Score can only reach this level when multiple high-
//                        confidence signals stack (e.g. homoglyph + bad TLD +
//                        login form + HTTP). Near-certain phishing page.
//    ≥ 60  Suspicious — A single homoglyph hit alone reaches this threshold.
//                        High-confidence individual signals land here.
//    ≥ 25  Warning    — Combination of lower-weight signals (suspicious TLD +
//                        keyword, or HTTP + deep subdomains). Warrants caution.
//     < 25  Safe      — No significant indicators detected.
// ---------------------------------------------------------------------------
function classifyThreat(score) {
  if (score >= 100) return "Dangerous";
  if (score >= 60) return "Suspicious";
  if (score >= 25) return "Warning";
  return "Safe";
}

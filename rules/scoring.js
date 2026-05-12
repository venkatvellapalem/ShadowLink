/**
 * scoring.js — ShadowLink Threat Intelligence Framework
 *
 * Score composition reference (weights):
 *   +70  Domain age < 30 days (very new)
 *   +60  Homoglyph / typosquat attack
 *   +40  Domain age 30–90 days
 *   +35  VirusTotal: malicious by 5+ vendors (high confidence)
 *   +30  Raw IP address URL
 *   +25  IDN / Punycode domain
 *   +20  Suspicious TLD
 *   +20  Login form on untrusted domain
 *   +15  HTTP (no encryption)
 *   +15  Excessive subdomain depth
 *   +15  VirusTotal: malicious by 1–4 vendors (low confidence, treat as caution)
 *   +10  VirusTotal: suspicious vendors
 *   +10  Suspicious keyword in domain
 *   +10  Unusually long URL
 *   +10  Open-redirect parameter
 *
 * Threshold rationale:
 *   ≥ 100  Dangerous  — Multiple high-confidence signals. Near-certain threat.
 *   ≥ 60   Suspicious — Single strong signal (homoglyph, new domain, etc.)
 *   ≥ 30   Warning    — Some signals present, warrants attention
 *   < 30   Safe       — No significant indicators
 */
function classifyThreat(score) {
  if (score >= 100) return "Dangerous";
  if (score >= 60) return "Suspicious";
  if (score >= 30) return "Warning";
  return "Safe";
}

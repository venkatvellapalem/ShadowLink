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
 * Threshold rationale (see classifyThreat below):
 *   ≥ 75  Dangerous  — Multiple high-confidence signals
 *   ≥ 50  Critical   — Strong signals present
 *   ≥ 25  Suspicious — Some signals, warrants attention
 *   < 25  Safe       — No significant indicators
 */
function classifyThreat(score) {

  if (score >= 75)
    return "Dangerous";

  if (score >= 50)
    return "Critical";

  if (score >= 25)
    return "Suspicious";

  return "Safe";
}
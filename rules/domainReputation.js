/**
 * domainReputation.js — ShadowLink Phishing Detection
 *
 * Standalone TLD reputation check. Acts as an independent verification layer
 * on top of urlAnalyzer.js — content.js adds extra weight for TLD hits that
 * come from this module separately.
 *
 * Uses the URL API to extract the hostname before comparing TLDs, so a URL
 * like "https://example.com/page.xyz" will never falsely trigger ".xyz".
 *
 * Depends on (loaded before this file per manifest.json):
 *   constants.js → suspiciousTLDs
 */

/* global suspiciousTLDs */

// ---------------------------------------------------------------------------
// checkSuspiciousTLD(url)
//
// @param  {string} url        — The full page URL
// @returns {string[]}          — Array of indicator strings (empty if clean)
// ---------------------------------------------------------------------------
function checkSuspiciousTLD(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    const indicators = [];

    // Prefer the global list from constants.js; fall back to a minimal
    // built-in set so this function works even if constants.js fails to load.
    const tlds =
      typeof suspiciousTLDs !== "undefined" && suspiciousTLDs.length > 0
        ? suspiciousTLDs
        : [".xyz", ".top", ".click", ".tk", ".gq", ".ml", ".cf", ".ga"];

    for (const tld of tlds) {
      if (hostname.endsWith(tld)) {
        indicators.push(`Suspicious TLD detected: ${tld}`);
        break; // One hit per URL is sufficient — avoid stacking the same signal
      }
    }

    return indicators;
  } catch {
    // Malformed URL — fail safe
    return [];
  }
}

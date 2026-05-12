/**
 * urlAnalyzer.js — ShadowLink Phishing Detection
 *
 * Produces a numeric risk score and a list of human-readable indicators for
 * a given URL. All hostname-based checks (TLD, brand keywords, homoglyphs)
 * are performed against parsed.hostname ONLY — never against the full URL
 * string — to prevent path/query contents from polluting domain analysis.
 *
 * Depends on (loaded before this file per manifest.json):
 *   constants.js      → trustedDomains, suspiciousKeywords, suspiciousTLDs
 *   homoglyph.js      → detectHomoglyphAttack(url)
 */

/* global trustedDomains, suspiciousKeywords, suspiciousTLDs, detectHomoglyphAttack */

// ---------------------------------------------------------------------------
// analyzeURL(url)
//
// @param  {string} url  — The full page URL (window.location.href)
// @returns {{ score: number, indicators: string[] }}
// ---------------------------------------------------------------------------
function analyzeURL(url) {
  let score = 0;
  const indicators = [];

  // --- Parse URL up front; bail cleanly on malformed input ---
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return { score: 0, indicators: [] };
  }

  // Normalised hostname without leading "www." — used for all domain checks
  const hostname = parsed.hostname.toLowerCase().replace(/^www\./, "");

  // -------------------------------------------------------------------------
  // Rule 1 — HTTP (unencrypted connection)
  //   +15 pts. Almost all legitimate services use HTTPS. HTTP is a strong
  //   early-warning signal, especially on credential pages.
  // -------------------------------------------------------------------------
  if (parsed.protocol === "http:") {
    score += 15;
    indicators.push("Connection is not encrypted (HTTP)");
  }

  // -------------------------------------------------------------------------
  // Rule 2 — Suspicious TLD
  //   +20 pts. Evaluated against hostname only. A URL like
  //   "example.com/something.xyz" will NOT trigger this rule.
  // -------------------------------------------------------------------------
  if (typeof suspiciousTLDs !== "undefined") {
    for (const tld of suspiciousTLDs) {
      if (hostname.endsWith(tld)) {
        score += 20;
        indicators.push(`Suspicious top-level domain: ${tld}`);
        break; // One match is enough — no need to keep scanning
      }
    }
  }

  // -------------------------------------------------------------------------
  // Rule 3 — Suspicious keywords in the domain label
  //   +10 pts per keyword. Only the hostname is scanned.
  //   Words like "login" legitimately appear in paths (e.g. github.com/login),
  //   so checking the full URL would generate constant false positives.
  // -------------------------------------------------------------------------
  if (typeof suspiciousKeywords !== "undefined") {
    for (const kw of suspiciousKeywords) {
      if (hostname.includes(kw)) {
        score += 10;
        indicators.push(`Suspicious keyword in domain: "${kw}"`);
      }
    }
  }

  // -------------------------------------------------------------------------
  // Rule 4 — Homoglyph / look-alike domain attack
  //   +60 pts per brand match. detectHomoglyphAttack() extracts and analyses
  //   only the registered domain label internally — path is never examined.
  // -------------------------------------------------------------------------
  if (typeof detectHomoglyphAttack !== "undefined") {
    const hMatches = detectHomoglyphAttack(url);
    for (const m of hMatches) {
      score += 60;
      indicators.push(m);
    }
  }

  // -------------------------------------------------------------------------
  // Rule 5 — Excessive subdomain depth
  //   +15 pts. Phishing pages often hide under deep subdomain structures to
  //   visually suggest legitimacy (e.g. paypal.com.login.verify.evil.xyz).
  //   Flag when there are more than 2 subdomains (parts.length > 4 means
  //   sub.sub.second-level.tld).
  // -------------------------------------------------------------------------
  const parts = hostname.split(".");
  if (parts.length > 4) {
    score += 15;
    indicators.push(
      `Excessive subdomain depth (${parts.length - 2} subdomains)`,
    );
  }

  // -------------------------------------------------------------------------
  // Rule 6 — Raw IP address
  //   +30 pts. Legitimate branded services never ask users to visit bare IPs.
  // -------------------------------------------------------------------------
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    score += 30;
    indicators.push("URL uses a raw IP address instead of a domain name");
  }

  // -------------------------------------------------------------------------
  // Rule 7 — Unusually long URL
  //   +10 pts. Very long URLs (>150 chars) frequently indicate encoded
  //   redirect chains or obfuscated query parameters used in phishing kits.
  // -------------------------------------------------------------------------
  if (url.length > 150) {
    score += 10;
    indicators.push(`Unusually long URL (${url.length} characters)`);
  }

  // -------------------------------------------------------------------------
  // Rule 8 — Internationalized Domain Name (IDN / Punycode)
  //   +25 pts. Punycode-encoded hostnames (xn--...) are a classic vector for
  //   IDN homograph attacks that bypass visual inspection.
  // -------------------------------------------------------------------------
  if (hostname.includes("xn--")) {
    score += 25;
    indicators.push(
      "Internationalized domain name detected (possible IDN homograph attack)",
    );
  }

  // -------------------------------------------------------------------------
  // Rule 9 — Credential stuffing redirect patterns in the query string
  //   +10 pts. Phishing kits routinely forward victims via open redirects
  //   with parameters like ?redirect=, ?return=, ?next=, ?url=.
  //   We only scan the query string here, NOT the hostname.
  // -------------------------------------------------------------------------
  const query = parsed.search.toLowerCase();
  const redirectParams = [
    "redirect=",
    "return=",
    "next=",
    "url=",
    "goto=",
    "returnurl=",
  ];
  for (const param of redirectParams) {
    if (query.includes(param)) {
      score += 10;
      indicators.push(
        `Open-redirect parameter detected in query: "${param.replace("=", "")}"`,
      );
      break;
    }
  }

  return { score, indicators };
}

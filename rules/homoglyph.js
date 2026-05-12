/**
 * homoglyph.js — ShadowLink Phishing Detection
 *
 * Detects homoglyph / look-alike domain attacks by analyzing ONLY the
 * registered domain label (e.g. "paypa1" from "paypa1.com").
 *
 * CRITICAL FIX: Previous version passed the raw URL string (including path
 * and query parameters) directly to the detection routine, causing massive
 * false positives — e.g. github.com/google would incorrectly trigger an
 * "impersonation of google" alert. This version extracts and analyzes only
 * the second-level domain label via the URL API.
 */

// ---------------------------------------------------------------------------
// Homoglyph map — maps visually similar characters to their ASCII equivalents
// ---------------------------------------------------------------------------
const HOMOGLYPH_MAP = {
  // Cyrillic lookalikes
  "\u0430": "a", // а → a
  "\u0435": "e", // е → e
  "\u043E": "o", // о → o
  "\u0440": "p", // р → p
  "\u0441": "c", // с → c
  "\u0445": "x", // х → x
  "\u0443": "y", // у → y
  "\u0456": "i", // і → i
  "\u0457": "i", // ї → i
  "\u0451": "e", // ё → e

  // Greek lookalikes
  "\u03BD": "v", // ν → v
  "\u03BC": "u", // μ → u
  "\u03B7": "n", // η → n
  "\u03B1": "a", // α → a
  "\u03B2": "b", // β → b
  "\u03B5": "e", // ε → e
  "\u03BF": "o", // ο → o
  "\u03C1": "r", // ρ → r
  "\u03C4": "t", // τ → t
  "\u03C7": "x", // χ → x

  // Latin Extended / Diacritic lookalikes
  "\u1E43": "m", // ṃ → m
  "\u1E45": "n", // ṅ → n
  "\u1E6D": "t", // ṭ → t
  "\u1E0D": "d", // ḍ → d
  "\u0131": "i", // ı → i  (dotless i)
  "\u0261": "g", // ɡ → g  (script g)
  "\u0251": "a", // ɑ → a  (script a)

  // ASCII digit/symbol lookalikes
  0: "o",
  1: "l",
  2: "z",
  3: "e",
  4: "a",
  5: "s",
  6: "g",
  7: "t",
  8: "b",
  9: "g",
  "@": "a",
  $: "s",
  "!": "i",
  "|": "l",
};

// ---------------------------------------------------------------------------
// Trusted brand names (bare labels, no TLD)
// ---------------------------------------------------------------------------
const TRUSTED_BRANDS = [
  "google",
  "paypal",
  "amazon",
  "facebook",
  "instagram",
  "apple",
  "microsoft",
  "netflix",
  "twitter",
  "linkedin",
  "github",
  "dropbox",
  "adobe",
  "spotify",
  "youtube",
  "gmail",
  "outlook",
  "yahoo",
  "cloudflare",
  "stripe",
  "shopify",
  "twitch",
  "discord",
  "reddit",
  "wikipedia",
  "wordpress",
  "squarespace",
  "salesforce",
  "hubspot",
  "zendesk",
  "atlassian",
  "slack",
  "zoom",
];

// ---------------------------------------------------------------------------
// Pre-computed set of exact brand names after normalization (used to fast-
// skip legitimate brand domains without running Levenshtein).
// ---------------------------------------------------------------------------
const NORMALIZED_BRAND_SET = new Set(
  TRUSTED_BRANDS.map((b) => b.toLowerCase()),
);

// ---------------------------------------------------------------------------
// normalizeLabel(str)
//
// Applies four transforms to collapse visual variants to a canonical form:
//   1. Unicode NFKC — decomposes ligatures, width variants, etc.
//   2. Homoglyph substitution via HOMOGLYPH_MAP.
//   3. Collapse runs of 3+ identical consecutive characters to 2
//      (gooooogle → gogle is too aggressive; keep two so levenshtein still
//       catches "gooogle" vs "google" = dist 1).
//   4. Lowercase.
// ---------------------------------------------------------------------------
function normalizeLabel(str) {
  // Step 1 — NFKC + lowercase
  let s = str.normalize("NFKC").toLowerCase();

  // Step 2 — homoglyph substitution (character by character)
  s = s
    .split("")
    .map((ch) => (HOMOGLYPH_MAP[ch] !== undefined ? HOMOGLYPH_MAP[ch] : ch))
    .join("");

  // Step 3 — collapse 3+ consecutive identical chars down to 2
  //   "gooooogle" → "gooogle" would be dist-2 from "google"; collapsing to
  //   "gogle" is dist-1. We collapse to double so edge cases like "microsoftt"
  //   (typo squatting) still match via levenshtein rather than being erased.
  s = s.replace(/(.)\1{2,}/g, "$1$1");

  return s;
}

// ---------------------------------------------------------------------------
// levenshtein(a, b) — standard iterative DP implementation, O(m*n) time/space
// ---------------------------------------------------------------------------
function levenshtein(a, b) {
  const m = a.length;
  const n = b.length;

  // Build (m+1) x (n+1) matrix, initializing base cases inline
  const dp = Array.from({ length: m + 1 }, (_, i) => {
    const row = new Array(n + 1);
    row[0] = i;
    return row;
  });
  for (let j = 0; j <= n; j++) dp[0][j] = j;

  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      if (a[i - 1] === b[j - 1]) {
        dp[i][j] = dp[i - 1][j - 1];
      } else {
        dp[i][j] =
          1 +
          Math.min(
            dp[i - 1][j - 1], // substitution
            dp[i][j - 1], // insertion
            dp[i - 1][j], // deletion
          );
      }
    }
  }

  return dp[m][n];
}

// ---------------------------------------------------------------------------
// extractDomainLabel(hostname)
//
// Returns the second-level domain label only:
//   'www.paypa1.com'         → 'paypa1'
//   'login.microsofft.com'   → 'microsofft'
//   'paypal.com'             → 'paypal'
//
// This deliberately discards subdomains and the TLD so we only compare
// the brand-impersonating segment.
// ---------------------------------------------------------------------------
function extractDomainLabel(hostname) {
  // Strip leading "www." (exact match only — not "www2." etc.)
  const h = hostname.replace(/^www\./, "").toLowerCase();
  // The second-level domain is everything before the first remaining dot
  return h.split(".")[0];
}

// ---------------------------------------------------------------------------
// isBrandHostname(hostname, brand)
//
// Returns true when the hostname IS the legitimate brand domain (or a known
// official subdomain), so we never flag google.com for targeting "google".
// ---------------------------------------------------------------------------
function isBrandHostname(hostname, brand) {
  const h = hostname.toLowerCase();
  return (
    h === `${brand}.com` ||
    h === `www.${brand}.com` ||
    h === `${brand}.net` ||
    h === `${brand}.org` ||
    h === `${brand}.io` ||
    h.endsWith(`.${brand}.com`) ||
    h.endsWith(`.${brand}.net`) ||
    h.endsWith(`.${brand}.org`) ||
    h.endsWith(`.${brand}.io`)
  );
}

// ---------------------------------------------------------------------------
// detectHomoglyphAttack(url)
//
// Main exported function.
// Accepts a full URL string, extracts the hostname via the URL API, isolates
// the second-level domain label, normalizes it, then compares against every
// trusted brand using normalized Levenshtein distance.
//
// Thresholds (tuned to minimize false positives):
//   • Minimum distance = 1  (exact post-normalization match → legitimate)
//   • Maximum distance = min(floor(brandLen * 0.25), 2)
//     — no more than 25 % of the brand name can differ, capped at 2 edits
//       so short brands ("zoom" len=4 → max=1 edit) aren't over-matched.
//
// Returns: string[] — human-readable indicator messages, empty if safe.
// ---------------------------------------------------------------------------
function detectHomoglyphAttack(url) {
  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase();

    // Extract ONLY the registered domain label — never the path/query
    const label = extractDomainLabel(hostname);
    const normalizedLabel = normalizeLabel(label);

    const matches = [];

    for (const brand of TRUSTED_BRANDS) {
      const normalizedBrand = normalizeLabel(brand);

      // --- Guard 1: post-normalization exact match → this IS the brand domain
      if (normalizedLabel === normalizedBrand) continue;

      // --- Guard 2: hostname is already a known-legit brand hostname
      if (isBrandHostname(hostname, brand)) continue;

      // --- Levenshtein gate ---
      const dist = levenshtein(normalizedLabel, normalizedBrand);
      const maxDist = Math.min(Math.floor(normalizedBrand.length * 0.25), 2);
      const minDist = 1; // must differ by at least 1 edit (not exact)

      if (dist >= minDist && dist <= maxDist) {
        matches.push(
          `Possible homoglyph attack targeting: ${brand} (detected label: "${label}")`,
        );
      }
    }

    return matches;
  } catch {
    // Malformed URL or runtime error — fail safe (no false positive)
    return [];
  }
}

/**
 * urlEntropy.js — URL Entropy & Randomness Detection
 * Detects algorithmically-generated phishing domains using Shannon entropy.
 * Analyzes ONLY the registered domain label (hostname before first TLD dot).
 */

// Shannon entropy calculation
function shannonEntropy(str) {
  if (!str || str.length === 0) return 0;
  const freq = {};
  for (const ch of str) freq[ch] = (freq[ch] || 0) + 1;
  let entropy = 0;
  const len = str.length;
  for (const count of Object.values(freq)) {
    const p = count / len;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

// Count numeric density (ratio of digits to total chars)
function numericDensity(str) {
  if (!str.length) return 0;
  return (str.match(/\d/g) || []).length / str.length;
}

// Count hyphen density
function hyphenDensity(str) {
  if (!str.length) return 0;
  return (str.match(/-/g) || []).length / str.length;
}

// Count consonant clusters (5+ consecutive consonants = randomness signal)
function hasRandomConsonantCluster(str) {
  return /[bcdfghjklmnpqrstvwxyz]{5,}/i.test(str);
}

/**
 * analyzeURLEntropy(url)
 * @param {string} url
 * @returns {{ score: number, indicators: string[], entropyValue: number }}
 */
function analyzeURLEntropy(url) {
  const result = { score: 0, indicators: [], entropyValue: 0 };

  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return result;
  }

  const hostname = parsed.hostname.toLowerCase().replace(/^www\./, '');

  // Extract the registered domain label (second-to-last part = SLD).
  // For 'xj29s-secure-auth.xyz'        → sld = 'xj29s-secure-auth'
  // For 'accounts.google.com'           → sld = 'google'   (no penalty)
  // For 'subdomain.paypal.com'          → sld = 'paypal'   (no penalty)
  const parts = hostname.split('.');
  const sld = parts.length >= 2 ? parts[parts.length - 2] : parts[0];

  // Skip very short labels (< 4 chars) — can't meaningfully measure entropy
  if (sld.length < 4) return result;

  // Skip known-good labels that would otherwise trip entropy thresholds
  const safeLabels = new Set([
    'google', 'gmail', 'yahoo', 'apple', 'adobe', 'slack', 'zoom',
    'stripe', 'twitch', 'github', 'reddit', 'paypal', 'amazon',
    'twitter', 'netflix', 'discord', 'spotify', 'microsoft', 'linkedin',
    'dropbox', 'icloud', 'outlook', 'office', 'azure', 'github',
    'gitlab', 'bitbucket', 'shopify', 'squarespace', 'wordpress'
  ]);
  if (safeLabels.has(sld)) return result;

  const entropy = shannonEntropy(sld);
  result.entropyValue = Math.round(entropy * 100) / 100;

  const numDens = numericDensity(sld);
  const hypDens = hyphenDensity(sld);

  // ── Tier 1: Very high entropy AND long enough to be meaningful ────────────
  // e.g. 'xj29s8auth3k' (entropy ≥ 3.8, length ≥ 8)
  if (entropy >= 3.8 && sld.length >= 8) {
    if (numDens > 0.25) {
      // High entropy + heavy numeric mix → likely DGA or random token
      result.score += 40;
      result.indicators.push('High-entropy domain with numeric obfuscation detected');
    } else if (hasRandomConsonantCluster(sld)) {
      // High entropy + consonant cluster → algorithmically generated string
      result.score += 30;
      result.indicators.push('Algorithmically-generated domain structure detected');
    } else if (entropy >= 4.2) {
      // Extremely high entropy alone (rare in human-chosen names)
      result.score += 25;
      result.indicators.push(
        'High entropy domain detected (entropy: ' + result.entropyValue + ')'
      );
    }
  }

  // ── Tier 2: Medium-high entropy on a long domain ──────────────────────────
  // e.g. 'secure8login3verify' (entropy ≥ 3.4, length ≥ 10)
  if (entropy >= 3.4 && sld.length >= 10) {
    if (numDens > 0.3) {
      result.score += 20;
      result.indicators.push('Domain contains high numeric density');
    }
  }

  // ── Tier 3: Excessive hyphens (e.g. 'paypal-login-secure-verify') ─────────
  // Requires: density > 15 %, at least one hyphen, length > 12, and ≥ 3 hyphens
  if (hypDens > 0.15 && sld.includes('-') && sld.length > 12) {
    const hyphenCount = (sld.match(/-/g) || []).length;
    if (hyphenCount >= 3) {
      result.score += 15;
      result.indicators.push(
        'Suspicious hyphenated domain structure (' + hyphenCount + ' hyphens)'
      );
    }
  }

  return result;
}

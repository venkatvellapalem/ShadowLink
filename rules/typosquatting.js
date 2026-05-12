/**
 * typosquatting.js — Enhanced Brand Impersonation Detection
 * Provides richer metadata about typosquatting attacks for UI display.
 *
 * Works alongside homoglyph.js — adds confidence scoring and attack-type
 * classification on top of the base levenshtein/homoglyph detection.
 *
 * Depends on (must load after):
 *   homoglyph.js  → TRUSTED_BRANDS, HOMOGLYPH_MAP, normalizeLabel,
 *                   levenshtein, extractDomainLabel, isBrandHostname,
 *                   detectHomoglyphAttack
 */

/* global TRUSTED_BRANDS, HOMOGLYPH_MAP, normalizeLabel, levenshtein, extractDomainLabel, isBrandHostname, detectHomoglyphAttack */

/**
 * classifyTyposquatAttack(label, brand)
 * Determines the specific technique used in a typosquatting attack.
 *
 * @param {string} label  — raw domain label  (e.g. 'paypa1')
 * @param {string} brand  — known brand name  (e.g. 'paypal')
 * @returns {string|null}  attack type key, or null if no clear attack
 */
function classifyTyposquatAttack(label, brand) {
  const nLabel = normalizeLabel(label);
  const nBrand = normalizeLabel(brand);

  // No difference after normalization → not an attack (or already caught by
  // homoglyph.js as an exact-after-normalize match)
  if (nLabel === nBrand) return null;

  // ── Repeated-letter attack: gooooogle, micrrosoft ────────────────────────
  // Three or more consecutive identical characters in the label
  if (/(.)\1{2,}/.test(label)) return 'repeated-letter';

  // ── Number-substitution attack: paypa1, micr0soft, g00gle ────────────────
  // Label contains digits AND the canonical brand does not → deliberate swap
  if (/[0-9]/.test(label) && !/[0-9]/.test(brand)) return 'number-substitution';

  // ── Character-substitution attack: 1-edit-distance (rnicrosoft → rn ≈ m) ─
  const dist = levenshtein(nLabel, nBrand);
  if (dist === 1) {
    // Same length → pure substitution; different length → insertion/deletion
    if (nLabel.length === nBrand.length) return 'character-substitution';
    return 'character-addition';
  }

  // ── Generic addition/transposition (2-char difference) ───────────────────
  if (Math.abs(nLabel.length - nBrand.length) === 1) return 'character-addition';

  // ── Fallback ──────────────────────────────────────────────────────────────
  return 'typosquat';
}

/**
 * analyzeTyposquatting(url)
 * Performs enhanced typosquatting analysis, complementing homoglyph.js.
 *
 * @param {string} url
 * @returns {{
 *   score:      number,
 *   indicators: string[],
 *   matches:    Array<{ brand: string, type: string, confidence: number, label: string }>
 * }}
 */
function analyzeTyposquatting(url) {
  const result = { score: 0, indicators: [], matches: [] };

  // Guard: only run when homoglyph.js has already been loaded
  if (typeof detectHomoglyphAttack !== 'function') return result;
  if (typeof normalizeLabel        !== 'function') return result;
  if (typeof levenshtein           !== 'function') return result;
  if (typeof extractDomainLabel    !== 'function') return result;
  if (typeof isBrandHostname       !== 'function') return result;

  try {
    const parsed   = new URL(url);
    const hostname = parsed.hostname.toLowerCase().replace(/^www\./, '');
    const label    = extractDomainLabel(hostname);

    if (!label || label.length < 3) return result;

    const brands = typeof TRUSTED_BRANDS !== 'undefined' ? TRUSTED_BRANDS : [];

    for (const brand of brands) {
      // Skip if the hostname IS the legitimate brand (e.g. paypal.com itself)
      if (isBrandHostname(hostname, brand)) continue;

      const nLabel = normalizeLabel(label);
      const nBrand = normalizeLabel(brand);

      // Exact match after normalization → already handled by homoglyph.js
      if (nLabel === nBrand) continue;

      // Short brands (≤ 3 chars) produce too many false positives with fuzzy
      // matching — skip them here; homoglyph.js handles those via exact checks
      if (nBrand.length <= 3) continue;

      const dist    = levenshtein(nLabel, nBrand);

      // Allow at most 25 % of the brand's length in edit distance, capped at 2.
      // e.g. 'paypal' (6 chars) → maxDist = min(1, 2) = 1
      //      'microsoft' (9 chars) → maxDist = min(2, 2) = 2
      const maxDist = Math.min(Math.floor(nBrand.length * 0.25), 2);

      if (dist < 1 || dist > maxDist) continue;

      // ── Attack identified ─────────────────────────────────────────────────
      const attackType = classifyTyposquatAttack(label, brand);
      if (attackType === null) continue; // normalizeLabel already made them equal

      // Confidence: how close to the brand (100 % = identical after norm)
      const confidence = Math.round((1 - dist / nBrand.length) * 100);

      result.matches.push({ brand, type: attackType, confidence, label });

      // ── Scoring by attack severity ────────────────────────────────────────
      // number-substitution (paypa1)     → most deliberate, highest score
      // character-substitution (rn → m)  → deliberate visual trick
      // repeated-letter (gooooogle)      → obvious parody/squatting pattern
      // character-addition / typosquat   → could be typo, lower score
      let pts;
      switch (attackType) {
        case 'number-substitution':   pts = 65; break;
        case 'character-substitution': pts = 60; break;
        case 'repeated-letter':        pts = 50; break;
        case 'character-addition':     pts = 45; break;
        default:                       pts = 50; break;
      }

      result.score += pts;

      // ── Human-readable indicator ──────────────────────────────────────────
      let typeLabel;
      switch (attackType) {
        case 'number-substitution':    typeLabel = 'Number substitution';   break;
        case 'character-substitution': typeLabel = 'Character substitution'; break;
        case 'repeated-letter':        typeLabel = 'Repeated-letter';        break;
        case 'character-addition':     typeLabel = 'Character addition';     break;
        default:                       typeLabel = 'Typosquatting';          break;
      }

      result.indicators.push(
        typeLabel + ' attack on ' + brand + ' (' + confidence + '% similarity)'
      );

      // Stop after the first match — one brand per URL is enough to flag
      break;
    }

  } catch {
    /* Silent — never surface detection errors to the page */
  }

  return result;
}

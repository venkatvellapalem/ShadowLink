# ShadowLink — Features

## Detection signals (weight)
Each rule contributes points. All accumulate via `threatEngine.addThreat(points, reason)`.

| Signal | Weight | Trigger | File |
|--------|--------|---------|------|
| Domain age < 30d | +70 | VT response | `content.js:336-338` |
| Homoglyph attack | +65 | `urlAnalyzer.js` calls `detectHomoglyph()` | `urlAnalyzer.js` |
| Typosquat score | up to +65 | `analyzeTyposquatting()` | `typosquatting.js` |
| Domain age 30–90d | +40 | VT response | `content.js:338-340` |
| VT malicious ≥ 10 | +70 | VT response | `content.js:348` |
| VT malicious ≥ 5 | +35 | VT response | `content.js:350` |
| VT malicious ≥ 2 | +20 | VT response | `content.js:352` |
| VT malicious = 1 | +10 | VT response | `content.js:354` |
| Suspicious TLD | +30 | `urlAnalyzer.js` + `checkSuspiciousTLD()` | `domainReputation.js` |
| Login form on untrusted | +20 | `detectLoginForms()` | `loginDetector.js` |
| HTTP (no encryption) | +15 | `urlAnalyzer.js` | `urlAnalyzer.js` |
| Suspicious keyword | +20 | `urlAnalyzer.js` — keywords in hostname | `urlAnalyzer.js` |
| URL entropy (DGA) | up to +40 | `analyzeURLEntropy()` | `urlEntropy.js` |
| URL shortener | +10 | `checkURLShortener()` | `urlShortener.js` |
| Credential leak | up to +50 | `detectCredentialThreats()` | `credentialLeak.js` |
| JS behavior (iframes, eval) | up to +35 | `analyzeJSBehavior()` | `jsBehavior.js` |
| Redirect chain | up to +35 | `analyzeRedirectChain()` | `redirectAnalyzer.js` |
| VT suspicious ≥ 3 | +15 | VT response | `content.js:358` |

## UI surfaces
- **Threat card** (`alertUI.js`): top-right glass card with score bar, indicators, shake on Dangerous, auto-dismiss timer
- **Warning banner** (`warningBanner.js`): bottom-right shield widget, click to dismiss
- **Danger overlay** (`dangerOverlay.js`): full-page block at score ≥ 100, "Proceed Anyway" button
- **Extension icon**: green/yellow/orange/red per threat level, orange while scanning
- **Screenshot capture**: triggered at score ≥ 50 via `CAPTURE_THREAT` message

## Background worker
- Pre-navigation scan checks URL before page loads
- Sets icon states (scanning orange → final color)
- Captures screenshots (max 10, dedup by URL within 5 min, 600ms delay)
- `importScripts` loads `rules/homoglyph.js` and `rules/constants.js` for worker access

## VirusTotal integration
- Calls `https://shadowlink-api.vercel.app/api/check?url=...`
- 10-second timeout via AbortController
- Extracts stats (harmless, malicious, suspicious, undetected)
- Extracts domain age from `domainAgeDays` / `domain_age_days` / WHOIS fallback
- Phase 2 runs after Phase 1; popup polls for `vtPending` flag every 500ms

## Homoglyph / typosquat detection
Two complementary layers:
1. `detectHomoglyph()` — exact-match after normalization → safe; near-miss after normalization → flagged. Normalization converts 0→o, 1→l, rn→m, removes separators.
2. `analyzeTyposquatting()` — catches attacks where normalization produces a different string. Classifies into: number-substitution, character-substitution, character-addition, repeated-letter.

Design gap: pure homoglyph domains that fully normalize to a brand (e.g. "paypa1" → "paypal") are NOT caught by either detector. They need a TLD/keyword/VT hit to flag.

## Threat classification
`classifyThreat()` in `scoring.js`:
- < 25 → Safe
- 25–49 → Suspicious
- 50–74 → Critical
- ≥ 75 → Dangerous

## Stabilization (completed)
- VT Phase-1/2 split so popup renders immediately
- Dead code removed (duplicate screenshots, 3rd Levenshtein copy, unused permissions, dead vars)
- Guards added for missing globals in `urlAnalyzer.js`
- All severity maps populated with `Critical`
- `typosquatting.js` references fixed (non-existent globals → existing ones)
- Ponytail cuts: iconMap shrunk, fromTab dead metadata deleted, skipPrefixes → regex
- 118 tests covering all rule files, threat engine, and edge cases

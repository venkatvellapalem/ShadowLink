# ShadowLink — Architecture

Chrome extension for real-time phishing detection. Content script analyzes pages in-browser, background worker coordinates cross-tab state.

## File layout

```
rules/             Detection engine (pure functions, no DOM)
  constants.js     trustedDomains[], suspiciousTLDs[], suspiciousKeywords[]
  homoglyph.js     levenshtein(), normalizeDomain(), detectHomoglyph()
  typosquatting.js analyzeTyposquatting(), classifyTyposquatAttack()
  scoring.js       classifyThreat(score)
  urlAnalyzer.js   analyzeURL(url) — TLD, HTTP, keywords, homoglyph
  domainReputation.js  checkSuspiciousTLD(url)
  urlShortener.js  checkURLShortener(url)
  urlEntropy.js    analyzeURLEntropy(url) — Shannon entropy, DGA detection
  loginDetector.js     detectLoginForms() — DOM: password fields, autocomplete
  credentialLeak.js    detectCredentialThreats() — DOM: HTTP creds, cross-domain
  jsBehavior.js        analyzeJSBehavior() — DOM: hidden iframes, eval patterns
  redirectAnalyzer.js  analyzeRedirectChain() — reads window.__slRedirectChain
  virusTotalCheck.js   checkVirusTotal(url) — calls shadowlink-api.vercel.app
core/
  threatEngine.js  createThreatEngine() — accumulator { score, indicators, breakdown, addThreat() }
ui/
  alertUI.js       showThreatPopup(result) — floating glassmorphism card
  warningBanner.js showWarningBanner(result) — bottom-right shield widget
  dangerOverlay.js showDangerOverlay(result) — full-page block for score ≥ 100
  design-system.css — CSS custom properties, keyframes, utility classes
popup/
  popup.js         Popup controller: VT polling, protocol badge, fallback
  popup.html       Popup layout
background.js      Service worker: pre-nav scanner, UPDATE_ICON, CAPTURE_THREAT
content.js         Main orchestrator: Phase 1 (sync) + Phase 2 (VT async)
storage/
  history.js       saveThreat() — persist threat records to storage
  timeline.js      saveTimelineEvent() — SOC timeline
manifest.json      Permissions, content_scripts, web_accessible_resources
test/
  rules_test.js    118 tests covering all rule files and threat engine
context/
  architecture.md  This file
  features.md      Feature descriptions
```

## Data flow

1. **Pre-navigation scan** (background.js): checks URL before page loads, sends SHOW_THREAT_POPUP if dangerous
2. **Content script loads** (content.js):
   - Phase 1 (sync): creates threat engine, runs all rules (URL analysis, login detection, entropy, shortener, JS behavior, credential leak, redirects, typosquatting), sets `window.shadowLinkData` with `vtPending: true`
   - Phase 2 (async): calls VirusTotal API, adds domain-age & VT-stats signals, sets final `window.shadowLinkData` with `vtPending: false`
3. **UI rendering**: icon update → floating card → banner → overlay → timeline → history → screenshot
4. **Popup**: reads `window.shadowLinkData`, polls every 500ms if `vtPending`

## Scoring

`classifyThreat(score)` thresholds:
- < 25   → Safe
- 25–49  → Suspicious
- 50–74  → Critical
- ≥ 75   → Dangerous

Danger overlay shown only at score ≥ 100. Threat card auto-dismisses at 10s (Suspicious) / 12s (Dangerous).

## Key constants (rules/constants.js)

- `trustedDomains[]` — 45 brand labels (google, paypal, microsoft…)
- `suspiciousTLDs[]` — 30+ high-abuse TLDs (.tk, .xyz, .top, .click…)
- `suspiciousKeywords[]` — 30+ phishing keywords (login, verify, secure, account…)

## Load order (manifest.json content_scripts)

constants.js → scoring.js → homoglyph.js → domainReputation.js → loginDetector.js → urlAnalyzer.js → virusTotalCheck.js → core/threatEngine.js → ui/alertUI.js → ui/warningBanner.js → storage/history.js → content.js

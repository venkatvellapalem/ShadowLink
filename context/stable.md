# ShadowLink — Stable baseline (July 2026)

All existing features are stabilized. No new functionality has been added — only fixes, dead code removal, and guardrails.

## What was done
- Fixed screenshot capture: `captureVisibleTab` was called with `tabId` instead of `windowId` (silent failure). Now resolves `windowId` via `chrome.tabs.get()` first. Fallback attempts capture without `windowId` for `chrome-extension://` pages.
- Fixed inconsistent icon updates (UPDATE_ICON message for scanning state)
- Fixed VT data missing on first visit (Phase-1/2 split with `vtPending` flag)
- Fixed broken typosquatting detection (non-existent global references)
- Removed dead code (duplicate screenshot, 3rd Levenshtein copy, unused permissions, unused vars)
- Added missing severity mappings (Critical everywhere)
- Added missing guards in urlAnalyzer.js (would crash if globals undefined)
- Simplified: collapsed helpers, regex over array+some, shared constants imports

## Known issues (pre-existing, not regressions)
1. **Pure homoglyph gap**: domains like "paypa1.com" that fully normalize to a brand ("paypal") are treated as safe by both `detectHomoglyph()` and `analyzeTyposquatting()`. Requires TLD/keyword/VT signal to flag.
2. **No automated tests for DOM-dependent rules**: `loginDetector.js`, `credentialLeak.js`, `jsBehavior.js`, `redirectAnalyzer.js` need a browser environment to test.
3. **VT API dependency**: VirusTotal checks go through `shadowlink-api.vercel.app` — if that's down, Phase 2 silently degrades (no VT score, no domain age).

## Test command
```
node test\rules_test.js
```
118 tests, 0 failures expected.

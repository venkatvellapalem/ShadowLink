/* =============================================================================
   ShadowLink — content.js
   Main content script · Orchestrates all page-level threat analysis
   =============================================================================
   Load order (per manifest.json):
     rules/constants.js → rules/scoring.js → rules/homoglyph.js
     → rules/domainReputation.js → rules/loginDetector.js
     → rules/urlAnalyzer.js → rules/virusTotalCheck.js
     → core/threatEngine.js → ui/alertUI.js → ui/warningBanner.js
     → storage/history.js → content.js  ← (this file, always last)
   ============================================================================= */

/* global createThreatEngine, analyzeURL, detectLoginForms, checkSuspiciousTLD,
           checkVirusTotal, classifyThreat, showThreatPopup, showWarningBanner,
           showDangerOverlay, saveThreat, analyzeURLEntropy, checkURLShortener,
           detectCredentialThreats, analyzeJSBehavior, analyzeTyposquatting,
           analyzeRedirectChain, saveTimelineEvent */

"use strict";
/*
|--------------------------------------------------------------------------
| REAL TARGET URL
|--------------------------------------------------------------------------
*/

let actualUrl = window.location.href;

try {

    /*
    |--------------------------------------------------------------------------
    | If current page is extension warning page,
    | extract original dangerous URL
    |--------------------------------------------------------------------------
    */

    if (
        window.location.protocol ===
        "chrome-extension:"
    ) {

        const params =
            new URLSearchParams(
                window.location.search
            );

        const originalUrl =
            params.get("url");

        if (originalUrl) {

            actualUrl = originalUrl;
        }
    }

}
catch (err) {

    console.warn(
        "[ShadowLink] URL extraction failed:",
        err
    );
}

// =============================================================================
// MESSAGE LISTENER — must be registered synchronously at the top level.
// Handles messages from the background service worker (e.g. SHOW_THREAT_POPUP
// when the pre-nav scanner wants the content script to surface a card before
// full analysis completes).
// =============================================================================

chrome.runtime.onMessage.addListener((message) => {
  if (
    message.type === "SHOW_THREAT_POPUP" &&
    typeof showThreatPopup === "function"
  ) {
    showThreatPopup(message.data);
  }
});

// =============================================================================
// MAIN ANALYSIS — async IIFE so we can await VirusTotal without blocking the
// message listener registration above.
// =============================================================================

(async () => {
  try {
    // -------------------------------------------------------------------------
    // 1. Initialise the threat accumulator engine
    // -------------------------------------------------------------------------
    /*
  Temporary bypass
*/

const bypass =

  sessionStorage.getItem(
    "shadowlink_bypass"
  );

if (bypass === "true") {

  console.log(
    "[ShadowLink] Protection bypassed once"
  );

  sessionStorage.removeItem(
    "shadowlink_bypass"
  );

  return;
}
    const engine = createThreatEngine();

    // Signal scanning started — set icon to orange immediately (scanning state)
    chrome.runtime.sendMessage({ type: "UPDATE_ICON", level: "Scanning" });

    // -------------------------------------------------------------------------
    // 2. URL structure analysis
    //    analyzeURL() returns { score, indicators[] }. We pass each indicator
    //    into the engine with context-aware point values so the engine's
    //    breakdown is always populated correctly.
    // -------------------------------------------------------------------------
const urlResult = analyzeURL(actualUrl);
    urlResult.indicators.forEach(indicator => {

  /*
    Homoglyph
  */

  if (
    indicator.includes("homoglyph")
  ) {

    engine.addThreat(
      65,
      indicator
    );
  }

  /*
    Suspicious TLD
  */

  else if (
    indicator.includes("TLD")
  ) {

    engine.addThreat(
      30,
      indicator
    );
  }

  /*
    HTTP
  */

  else if (
  indicator.toLowerCase().includes("http")
) {

    engine.addThreat(
      15,
      indicator
    );
  }

  /*
    Suspicious keywords
  */

  else if (
    indicator.includes("keyword")
  ) {

    engine.addThreat(
      20,
      indicator
    );
  }

  /*
    Default
  */

  else {

    engine.addThreat(
      10,
      indicator
    );
  }
});

    // -------------------------------------------------------------------------
    // 3. Login form detection
    //    Each indicator from detectLoginForms() is worth 20 pts.
    // -------------------------------------------------------------------------
    const loginIndicators = detectLoginForms();
    loginIndicators.forEach((ind) => engine.addThreat(20, ind));

    // -------------------------------------------------------------------------
    // 3b. URL Entropy analysis
    // -------------------------------------------------------------------------
    if (typeof analyzeURLEntropy === "function") {
      const entropyResult = analyzeURLEntropy(actualUrl);
      entropyResult.indicators.forEach((ind) =>
        engine.addThreat(
          entropyResult.score > 0
            ? Math.round(
                entropyResult.score /
                  Math.max(entropyResult.indicators.length, 1),
              )
            : 10,
          ind,
        ),
      );
    }

    // -------------------------------------------------------------------------
    // 3c. URL Shortener check
    // -------------------------------------------------------------------------
    if (typeof checkURLShortener === "function") {
      const shortResult = checkURLShortener(actualUrl);
      shortResult.indicators.forEach((ind) => engine.addThreat(10, ind));
    }

    // -------------------------------------------------------------------------
    // 3d. JS Behavior analysis
    // -------------------------------------------------------------------------
    if (typeof analyzeJSBehavior === "function") {
      const jsResult = analyzeJSBehavior();
      jsResult.indicators.forEach((ind) => {
        // Map score proportionally per indicator
        const pts =
          jsResult.indicators.length > 0
            ? Math.round(jsResult.score / jsResult.indicators.length)
            : 10;
        engine.addThreat(pts, ind);
      });
    }

    // -------------------------------------------------------------------------
    // 3e. Credential harvesting detection
    // -------------------------------------------------------------------------
    if (typeof detectCredentialThreats === "function") {
      const credResult = detectCredentialThreats();
      credResult.indicators.forEach((ind) => {
        const pts =
          credResult.indicators.length > 0
            ? Math.round(credResult.score / credResult.indicators.length)
            : 15;
        engine.addThreat(pts, ind);
      });
    }

    // -------------------------------------------------------------------------
    // 3f. Redirect chain analysis
    // -------------------------------------------------------------------------
    if (typeof analyzeRedirectChain === "function") {
      const rdResult = analyzeRedirectChain();
      rdResult.indicators.forEach((ind) => {
        const pts =
          rdResult.indicators.length > 0
            ? Math.round(rdResult.score / rdResult.indicators.length)
            : 10;
        engine.addThreat(pts, ind);
      });
    }

    // -------------------------------------------------------------------------
    // 3g. Typosquatting classification
    // -------------------------------------------------------------------------
    if (typeof analyzeTyposquatting === "function") {
      const typosquatResult = analyzeTyposquatting(actualUrl);
      typosquatResult.indicators.forEach((ind) => {
        const pts =
          typosquatResult.indicators.length > 0
            ? Math.round(typosquatResult.score / typosquatResult.indicators.length)
            : 10;
        engine.addThreat(pts, ind);
      });
    }

    // -------------------------------------------------------------------------
    // 4. Suspicious TLD check (deduplication)
    //    checkSuspiciousTLD() may overlap with urlAnalyzer — skip if the engine
    //    already has a TLD-related indicator to avoid double-counting.
    // -------------------------------------------------------------------------
    const tldIndicators = checkSuspiciousTLD(actualUrl);
    tldIndicators.forEach((ind) => {
      const alreadyFlagged = engine.indicators.some(
        (i) =>
          i.toLowerCase().includes("tld") ||
          i.toLowerCase().includes("top-level domain"),
      );
      if (!alreadyFlagged) engine.addThreat(30, ind);
    });

    // -------------------------------------------------------------------------
    // Phase 1: Synchronous analysis complete — set preliminary result so the
    // popup can read window.shadowLinkData immediately (even before VT).
    // -------------------------------------------------------------------------
    const preliminaryResult = {
      score: engine.score,
      indicators: engine.indicators,
      breakdown: engine.breakdown,
      threatLevel: classifyThreat(engine.score),
      vtStats: null,
      domainAgeDays: null,
      vtPending: true,
      url: actualUrl,
      protocol: new URL(actualUrl).protocol,
      timestamp: new Date().toLocaleString(),
    };
    window.shadowLinkData = preliminaryResult;

    // -------------------------------------------------------------------------
    // Phase 2: VirusTotal + Domain Age (async, network call)
    // -------------------------------------------------------------------------
    let vtStats = null;
    let domainAgeDays = null;

    try {
      const vtResult = await checkVirusTotal(actualUrl);
      if (vtResult) {
        vtStats = vtResult.stats;
        domainAgeDays = vtResult.domainAgeDays;
      }
    } catch (vtErr) {
      console.warn("[ShadowLink] VirusTotal check failed:", vtErr);
    }

    if (domainAgeDays !== null && domainAgeDays !== undefined) {
      if (domainAgeDays < 30) {
        engine.addThreat(70, `Very new domain: registered ${domainAgeDays} days ago`);
      } else if (domainAgeDays < 90) {
        engine.addThreat(40, `Recently registered domain: ${domainAgeDays} days ago`);
      }
    }

    if (vtStats) {
      const malicious = vtStats.malicious || 0;
      const suspicious = vtStats.suspicious || 0;

      if (malicious >= 10) {
        engine.addThreat(70, `VirusTotal: flagged malicious by ${malicious} vendors`);
      } else if (malicious >= 5) {
        engine.addThreat(35, `VirusTotal: flagged malicious by ${malicious} vendors`);
      } else if (malicious >= 2) {
        engine.addThreat(20, `VirusTotal: flagged by ${malicious} vendor(s)`);
      } else if (malicious === 1) {
        engine.addThreat(10, `VirusTotal: 1 vendor flagged (low confidence)`);
      }

      if (suspicious >= 3) {
        engine.addThreat(15, `VirusTotal: flagged suspicious by ${suspicious} vendors`);
      } else if (suspicious > 0) {
        engine.addThreat(5, `VirusTotal: ${suspicious} vendor(s) flagged suspicious`);
      }
    }

    // -------------------------------------------------------------------------
    // 6. Build final result with VT data
    // -------------------------------------------------------------------------
    const finalResult = {
      score: engine.score,
      indicators: engine.indicators,
      breakdown: engine.breakdown,
      threatLevel: classifyThreat(engine.score),
      vtStats,
      domainAgeDays,
      vtPending: false,
      url: actualUrl,
      protocol: new URL(actualUrl).protocol,
      timestamp: new Date().toLocaleString(),
    };

    window.shadowLinkData = finalResult;

    // -------------------------------------------------------------------------
    // 7. Dynamic Extension Icon
    // -------------------------------------------------------------------------
    try {
      let iconPath = {
        16: "assets/icons/icon16.png",
        32: "assets/icons/icon32.png",
        48: "assets/icons/icon48.png",
        128: "assets/icons/icon128.png"
      };

      const level = finalResult.threatLevel?.toLowerCase();

      if (level === "safe") {
        iconPath = {
          16: chrome.runtime.getURL("assets/icons/green16.png"),
          32: chrome.runtime.getURL("assets/icons/green32.png"),
          48: chrome.runtime.getURL("assets/icons/green48.png"),
          128: chrome.runtime.getURL("assets/icons/green128.png")
        };
      } else if (level === "suspicious") {
        iconPath = {
          16: chrome.runtime.getURL("assets/icons/yellow16.png"),
          32: chrome.runtime.getURL("assets/icons/yellow32.png"),
          48: chrome.runtime.getURL("assets/icons/yellow48.png"),
          128: chrome.runtime.getURL("assets/icons/yellow128.png")
        };
      } else if (level === "critical") {
        iconPath = {
          16: chrome.runtime.getURL("assets/icons/orange16.png"),
          32: chrome.runtime.getURL("assets/icons/orange32.png"),
          48: chrome.runtime.getURL("assets/icons/orange48.png"),
          128: chrome.runtime.getURL("assets/icons/orange128.png")
        };
      } else if (level === "dangerous") {
        iconPath = {
          16: chrome.runtime.getURL("assets/icons/red16.png"),
          32: chrome.runtime.getURL("assets/icons/red32.png"),
          48: chrome.runtime.getURL("assets/icons/red48.png"),
          128: chrome.runtime.getURL("assets/icons/red128.png")
        };
      }

      chrome.runtime.sendMessage({ type: "SET_EXTENSION_ICON", iconPath });
    } catch (err) {
      console.warn("Dynamic icon update failed:", err);
    }

    // -------------------------------------------------------------------------
    // 8. Show floating threat card and warning banner for non-Safe results
    // -------------------------------------------------------------------------
    if (finalResult.threatLevel !== "Safe") {
      if (typeof showThreatPopup === "function") showThreatPopup(finalResult);
      if (typeof showWarningBanner === "function") showWarningBanner(finalResult);
    }

    // Show full-page overlay for dangerous scores (≥ 100: multiple high-confidence signals)
    if (finalResult.score >= 100 && typeof showDangerOverlay === "function") {
      showDangerOverlay(finalResult);
    }

    // -------------------------------------------------------------------------
    // 9. Save to SOC threat timeline
    // -------------------------------------------------------------------------
    if (typeof saveTimelineEvent === "function") {
      saveTimelineEvent(finalResult);
    }

    // -------------------------------------------------------------------------
    // 10. Persist to threat history for non-safe results
    // -------------------------------------------------------------------------
    if (finalResult.threatLevel !== "Safe" && typeof saveThreat === "function") {
      saveThreat(finalResult);
    }

    // -------------------------------------------------------------------------
    // 11. Request screenshot evidence capture for medium+ risk scores
    // -------------------------------------------------------------------------
    if (finalResult.score >= 50) {
      chrome.runtime.sendMessage({ type: "CAPTURE_THREAT", url: actualUrl });
    }

    console.log("[ShadowLink] Analysis complete:", finalResult);
  } catch (err) {
    // Never let analysis errors surface to the user as uncaught exceptions
    console.error("[ShadowLink] Analysis error:", err);
  }
})();

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
          checkVirusTotal, classifyThreat, showThreatPopup, saveThreat */

"use strict";

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
    const engine = createThreatEngine();

    // -------------------------------------------------------------------------
    // 2. URL structure analysis
    //    analyzeURL() returns { score, indicators[] }. We pass each indicator
    //    into the engine with context-aware point values so the engine's
    //    breakdown is always populated correctly.
    // -------------------------------------------------------------------------
    const urlResult = analyzeURL(window.location.href);

    urlResult.indicators.forEach((indicator) => {
      const lower = indicator.toLowerCase();
      let points;

      if (lower.includes("homoglyph")) points = 60;
      else if (lower.includes("punycode") || lower.includes("idn")) points = 25;
      else if (lower.includes("ip address")) points = 30;
      else if (lower.includes("http")) points = 15;
      else points = 20;

      engine.addThreat(points, indicator);
    });

    // -------------------------------------------------------------------------
    // 3. Login form detection
    //    Each indicator from detectLoginForms() is worth 20 pts.
    // -------------------------------------------------------------------------
    const loginIndicators = detectLoginForms();
    loginIndicators.forEach((ind) => engine.addThreat(20, ind));

    // -------------------------------------------------------------------------
    // 4. Suspicious TLD check (deduplication)
    //    checkSuspiciousTLD() may overlap with urlAnalyzer — skip if the engine
    //    already has a TLD-related indicator to avoid double-counting.
    // -------------------------------------------------------------------------
    const tldIndicators = checkSuspiciousTLD(window.location.href);
    tldIndicators.forEach((ind) => {
      const alreadyFlagged = engine.indicators.some(
        (i) =>
          i.toLowerCase().includes("tld") ||
          i.toLowerCase().includes("top-level domain"),
      );
      if (!alreadyFlagged) engine.addThreat(30, ind);
    });

    // -------------------------------------------------------------------------
    // 5. VirusTotal + Domain Age (async, network call)
    //    Wrapped in its own try/catch so a VT failure never aborts analysis.
    // -------------------------------------------------------------------------
    let vtStats = null;
    let domainAgeDays = null;

    try {
      const vtResult = await checkVirusTotal(window.location.href);
      if (vtResult) {
        vtStats = vtResult.stats;
        domainAgeDays = vtResult.domainAgeDays;
      }
    } catch (vtErr) {
      console.warn("[ShadowLink] VirusTotal check failed:", vtErr);
    }

    // Domain age scoring
    if (domainAgeDays !== null && domainAgeDays !== undefined) {
      if (domainAgeDays < 30) {
        engine.addThreat(
          70,
          `Very new domain: registered ${domainAgeDays} days ago`,
        );
      } else if (domainAgeDays < 90) {
        engine.addThreat(
          40,
          `Recently registered domain: ${domainAgeDays} days ago`,
        );
      }
    }

    // VirusTotal malicious / suspicious scoring
    if (vtStats) {
      const malicious = vtStats.malicious || 0;
      const suspicious = vtStats.suspicious || 0;

      if (malicious >= 5) {
        engine.addThreat(
          80,
          `VirusTotal: flagged malicious by ${malicious} vendors`,
        );
      } else if (malicious > 0) {
        engine.addThreat(40, `VirusTotal: flagged by ${malicious} vendor(s)`);
      }

      if (suspicious > 0) {
        engine.addThreat(
          30,
          `VirusTotal: flagged suspicious by ${suspicious} vendors`,
        );
      }
    }

    // -------------------------------------------------------------------------
    // 6. Build the final result object
    //    This is stored on window so popup.js can read it via executeScript.
    // -------------------------------------------------------------------------
    const finalResult = {
      score: engine.score,
      indicators: engine.indicators,
      breakdown: engine.breakdown,
      threatLevel: classifyThreat(engine.score),
      vtStats,
      domainAgeDays,
      url: window.location.href,
      protocol: window.location.protocol, // 'https:' or 'http:'
      timestamp: new Date().toLocaleString(),
    };

    // Expose globally — popup reads this via chrome.scripting.executeScript
    window.shadowLinkData = finalResult;

    console.log("[ShadowLink] Analysis complete:", finalResult);

    // -------------------------------------------------------------------------
    // 7. Show floating threat card for Suspicious / Dangerous / Warning levels
    // -------------------------------------------------------------------------
    if (
      finalResult.threatLevel !== "Safe" &&
      typeof showThreatPopup === "function"
    ) {
      showThreatPopup(finalResult);
    }

    // -------------------------------------------------------------------------
    // 8. Update extension action icon to reflect final threat level
    // -------------------------------------------------------------------------
    chrome.runtime.sendMessage({
      type: "UPDATE_ICON",
      level: finalResult.threatLevel,
    });

    // -------------------------------------------------------------------------
    // 9. Persist to threat history for non-safe results
    // -------------------------------------------------------------------------
    if (
      finalResult.threatLevel !== "Safe" &&
      typeof saveThreat === "function"
    ) {
      saveThreat(finalResult);
    }

    // -------------------------------------------------------------------------
    // 10. Request screenshot evidence capture for medium+ risk scores
    // -------------------------------------------------------------------------
    if (finalResult.score >= 50) {
      chrome.runtime.sendMessage({
        type: "CAPTURE_THREAT",
        url: window.location.href,
      });
    }
  } catch (err) {
    // Never let analysis errors surface to the user as uncaught exceptions
    console.error("[ShadowLink] Analysis error:", err);
  }
})();

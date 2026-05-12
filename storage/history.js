/* =============================================================================
   ShadowLink — storage/history.js
   Threat history persistence · chrome.storage.local
   ============================================================================= */

"use strict";

/**
 * saveThreat(result)
 *
 * Persists a non-safe analysis result to the extension's local storage.
 * Entries are stored newest-first and the list is capped at 50 items so
 * storage usage stays bounded even for heavy users.
 *
 * @param {Object} result        — Final result object from content.js
 * @param {string} result.threatLevel
 * @param {number} result.score
 * @param {string[]} result.indicators
 */
function saveThreat(result) {
  // Never persist Safe-level pages — they are not actionable history entries
  if (!result || result.threatLevel === "Safe") return;

  chrome.storage.local.get(["shadowlinkHistory"], (data) => {
    const history = data.shadowlinkHistory || [];

    history.unshift({
      url: window.location.href,
      threatLevel: result.threatLevel,
      score: result.score,
      indicators: result.indicators || [],
      timestamp: new Date().toLocaleString(),
    });

    // Keep only the 50 most recent threat records
    chrome.storage.local.set({
      shadowlinkHistory: history.slice(0, 50),
    });
  });
}

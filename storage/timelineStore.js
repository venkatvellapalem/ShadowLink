/**
 * timelineStore.js — SOC Threat Timeline Storage
 * Stores detailed threat events for the timeline view.
 */

"use strict";

const TIMELINE_KEY = "shadowlinkTimeline";
const TIMELINE_MAX = 100;

/**
 * saveTimelineEvent(event)
 * @param {{ url: string, threatLevel: string, score: number, indicators: string[],
 *           breakdown: any[], timestamp: string, category: string }} event
 */
function saveTimelineEvent(event) {
  if (!event || event.threatLevel === "Safe") return;

  chrome.storage.local.get([TIMELINE_KEY], (data) => {
    const timeline = data[TIMELINE_KEY] || [];

    timeline.unshift({
      id: Date.now(),
      url: event.url || window.location.href,
      hostname: (() => {
        try {
          return new URL(event.url || window.location.href).hostname;
        } catch {
          return "unknown";
        }
      })(),
      threatLevel: event.threatLevel,
      score: event.score,
      indicators: event.indicators || [],
      breakdown: event.breakdown || [],
      timestamp: event.timestamp || new Date().toLocaleString(),
      category: detectThreatCategory(event.indicators || []),
    });

    chrome.storage.local.set({
      [TIMELINE_KEY]: timeline.slice(0, TIMELINE_MAX),
    });
  });
}

/**
 * detectThreatCategory(indicators)
 * Maps indicator strings to a human-readable threat category label.
 * @param {string[]} indicators
 * @returns {string}
 */
function detectThreatCategory(indicators) {
  const text = indicators.join(" ").toLowerCase();

  if (
    text.includes("homoglyph") ||
    text.includes("typosquat") ||
    text.includes("character sub") ||
    text.includes("number sub")
  )
    return "Brand Impersonation";

  if (
    text.includes("credential") ||
    text.includes("password") ||
    text.includes("login form")
  )
    return "Credential Theft";

  if (text.includes("redirect")) return "Redirect Chain";

  if (text.includes("entropy") || text.includes("algorithmically"))
    return "Entropy Attack";

  if (text.includes("tld") || text.includes("top-level"))
    return "Suspicious TLD";

  if (text.includes("virustotal") || text.includes("malicious"))
    return "Known Malware";

  if (text.includes("obfuscated") || text.includes("iframe"))
    return "JS Threat";

  if (text.includes("new domain") || text.includes("recently registered"))
    return "New Domain";

  return "Phishing Attempt";
}

/**
 * getTimeline(callback)
 * @param {(timeline: object[]) => void} callback
 */
function getTimeline(callback) {
  chrome.storage.local.get([TIMELINE_KEY], (data) => {
    callback(data[TIMELINE_KEY] || []);
  });
}

/**
 * clearTimeline(callback)
 * @param {() => void} [callback]
 */
function clearTimeline(callback) {
  chrome.storage.local.remove([TIMELINE_KEY], callback);
}

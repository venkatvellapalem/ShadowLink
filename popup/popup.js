/* =============================================================================
   ShadowLink — popup/popup.js
   Extension popup controller · Reads window.shadowLinkData via executeScript
   ============================================================================= */

"use strict";

// =============================================================================
// TAB SWITCHING
// Activates the correct panel and marks the correct button as selected.
// =============================================================================

document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    // Deactivate all buttons and panels
    document.querySelectorAll(".tab-btn").forEach((b) => {
      b.classList.remove("active");
      b.setAttribute("aria-selected", "false");
    });
    document
      .querySelectorAll(".tab-panel")
      .forEach((p) => p.classList.remove("active"));

    // Activate the clicked button and its corresponding panel
    btn.classList.add("active");
    btn.setAttribute("aria-selected", "true");

    const panel = document.getElementById("tab-" + btn.dataset.tab);
    if (panel) panel.classList.add("active");
  });
});

// =============================================================================
// THREAT LEVEL STYLING
// Applies colour, label, ring animation, and accessory element updates.
// =============================================================================

/**
 * @typedef {{ color: string, label: string }} ThreatConfig
 */

/** @type {Record<string, ThreatConfig>} */
const THREAT_CONFIGS = {
  Safe: { color: "#00F5D4", label: "No threats detected" },
  Warning: { color: "#F59E0B", label: "Minor issues detected" },
  Caution: { color: "#F59E0B", label: "Proceed with caution" },
  Suspicious: { color: "#F97316", label: "Suspicious activity detected" },
  Dangerous: { color: "#EF4444", label: "Dangerous — do not proceed" },
};

/**
 * applyThreatStyling(threatLevel, score)
 *
 * Updates every dynamic UI element in the popup to reflect the given threat
 * level and numeric risk score.
 *
 * @param {string} threatLevel - One of: Safe | Warning | Caution | Suspicious | Dangerous
 * @param {number} score       - Raw numeric risk score (0–150+)
 */
function applyThreatStyling(threatLevel, score) {
  const cfg = THREAT_CONFIGS[threatLevel] || THREAT_CONFIGS.Safe;

  // --- Threat level label ---
  const tlEl = document.getElementById("threatLevel");
  if (tlEl) {
    tlEl.textContent = threatLevel;
    tlEl.style.color = cfg.color;
  }

  // --- Sub-label ---
  const subEl = document.getElementById("threatSublabel");
  if (subEl) subEl.textContent = cfg.label;

  // --- Numeric risk score ---
  const scoreEl = document.getElementById("riskScore");
  if (scoreEl) {
    scoreEl.textContent = Math.min(score, 999);
    scoreEl.style.color = cfg.color;
  }

  // --- SVG progress ring ---
  // The ring uses stroke-dashoffset to animate from empty (full offset) to
  // a fraction of the circumference that represents the score percentage.
  const ringFill = document.getElementById("ringFill");
  if (ringFill) {
    const r = 40; // matches SVG r attribute
    const circumference = 2 * Math.PI * r; // ≈ 251.33
    const pct = Math.min(score / 150, 1); // score/150 → 0..1
    const targetOffset = circumference * (1 - pct);

    // Apply static properties immediately
    ringFill.style.stroke = cfg.color;
    ringFill.style.strokeDasharray = circumference;
    ringFill.style.filter = `drop-shadow(0 0 6px ${cfg.color})`;

    // Start at zero fill (full offset), then animate to the target offset
    ringFill.style.transition = "none";
    ringFill.style.strokeDashoffset = circumference;

    // Defer so the browser paints the starting state before the transition
    setTimeout(() => {
      ringFill.style.transition =
        "stroke-dashoffset 1s cubic-bezier(0.16,1,0.3,1)";
      ringFill.style.strokeDashoffset = targetOffset;
    }, 50);
  }

  // --- Shield icon glow ---
  const shieldEl = document.getElementById("shieldIcon");
  if (shieldEl) shieldEl.style.filter = `drop-shadow(0 0 8px ${cfg.color})`;

  // --- Pulse dot colour ---
  const dotEl = document.getElementById("pulseDot");
  if (dotEl) {
    dotEl.style.background = cfg.color;
    dotEl.style.boxShadow = `0 0 8px ${cfg.color}`;
  }

  // --- Protection badge border ---
  const badgeEl = document.getElementById("protectionBadge");
  if (badgeEl) badgeEl.style.borderColor = `${cfg.color}40`;

  // --- Protection status text ---
  const statusEl = document.getElementById("protectionStatus");
  if (statusEl)
    statusEl.textContent = threatLevel === "Safe" ? "Protected" : threatLevel;
}

// =============================================================================
// THREAT BREAKDOWN RENDERER
// Populates the per-rule score breakdown card.
// =============================================================================

/**
 * renderBreakdown(breakdown)
 * @param {{ points: number, reason: string }[]} breakdown
 */
function renderBreakdown(breakdown) {
  const el = document.getElementById("breakdown");
  if (!el) return;

  if (!breakdown || breakdown.length === 0) {
    el.innerHTML = `
      <div class="no-threat-msg">
        <span class="no-threat-icon">✓</span>
        All security checks passed
      </div>`;
    return;
  }

  el.innerHTML = breakdown
    .map(
      (item) => `
      <div class="breakdown-item">
        <span class="breakdown-score">+${item.points}</span>
        <span class="breakdown-reason">${item.reason}</span>
      </div>`,
    )
    .join("");
}

// =============================================================================
// VIRUSTOTAL STATS RENDERER
// Fills the VT stat cells and the domain age badge.
// =============================================================================

/**
 * renderVTStats(vtStats, domainAgeDays)
 * @param {{ harmless?: number, malicious?: number, suspicious?: number, undetected?: number }|null} vtStats
 * @param {number|null} domainAgeDays
 */
function renderVTStats(vtStats, domainAgeDays) {
  if (vtStats) {
    const setNum = (id, val) => {
      const el = document.getElementById(id);
      if (el) el.textContent = val ?? 0;
    };

    setNum("vtCleanNum", vtStats.harmless || 0);
    setNum("vtMaliciousNum", vtStats.malicious || 0);
    setNum("vtSuspiciousNum", vtStats.suspicious || 0);
    setNum("vtUndetectedNum", vtStats.undetected || 0);
  }

  // --- Domain age badge ---
  const ageEl = document.getElementById("domainAge");
  if (ageEl && domainAgeDays !== null && domainAgeDays !== undefined) {
    if (domainAgeDays < 30) {
      ageEl.textContent = `${domainAgeDays}d old · New Domain`;
    } else if (domainAgeDays < 365) {
      ageEl.textContent = `${domainAgeDays}d old`;
    } else {
      ageEl.textContent = `${Math.floor(domainAgeDays / 365)}y old domain`;
    }
    ageEl.style.color = domainAgeDays < 90 ? "#F97316" : "";
  }
}

// =============================================================================
// SCREENSHOT GALLERY RENDERER
// =============================================================================

/**
 * renderScreenshots(screenshots)
 * @param {{ screenshot: string, url: string, timestamp: string }[]} screenshots
 */
function renderScreenshots(screenshots) {
  const container = document.getElementById("screenshots");
  if (!container) return;

  if (!screenshots || screenshots.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">📷</div>
        <div>No evidence captured</div>
      </div>`;
    return;
  }

  container.innerHTML = screenshots
    .map((item) => {
      // Truncate long URLs to 50 chars for display
      const displayUrl =
        item.url.length > 50 ? item.url.substring(0, 47) + "..." : item.url;

      return `
        <div class="screenshot-item">
          <img src="${item.screenshot}" alt="Captured evidence screenshot" />
          <div class="screenshot-meta">${displayUrl}</div>
          <div class="screenshot-time">${item.timestamp}</div>
        </div>`;
    })
    .join("");
}

// =============================================================================
// THREAT HISTORY RENDERER
// =============================================================================

/** Colour map for threat level badges in the history list */
const HISTORY_COLORS = {
  Warning: "#F59E0B",
  Caution: "#F59E0B",
  Suspicious: "#F97316",
  Dangerous: "#EF4444",
};

/**
 * renderHistory(history)
 * @param {{ threatLevel: string, score: number, url: string, timestamp: string }[]} history
 */
function renderHistory(history) {
  const container = document.getElementById("history");
  if (!container) return;

  if (!history || history.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">🔍</div>
        <div>No threats detected</div>
      </div>`;
    return;
  }

  container.innerHTML = history
    .map((item) => {
      const color = HISTORY_COLORS[item.threatLevel] || "#00F5D4";
      const border = `${color}40`;

      return `
        <div class="history-item">
          <div class="history-header">
            <span class="history-badge"
                  style="color:${color};border-color:${border}">
              ${item.threatLevel}
            </span>
            <span class="history-score">Score: ${item.score}</span>
          </div>
          <div class="history-url">${item.url}</div>
          <div class="history-time">${item.timestamp}</div>
        </div>`;
    })
    .join("");
}

// =============================================================================
// MAIN INIT — runs when popup.html finishes loading
// =============================================================================

chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
  const tab = tabs[0];
  if (!tab) return;

  // --- Display the current site URL (truncated) ---
  const siteEl = document.getElementById("site");
  if (siteEl) {
    try {
      const parsed = new URL(tab.url);
      // Show hostname + up to 30 chars of path
      siteEl.textContent = parsed.hostname + parsed.pathname.substring(0, 30);
    } catch {
      siteEl.textContent = tab.url.substring(0, 50);
    }
  }

  // --- Protocol badge (HTTPS / HTTP) — hoisted so executeScript closure can refine it ---
  const protoEl = document.getElementById("protocol");
  if (protoEl) {
    const isHttps = tab.url.startsWith("https");
    protoEl.textContent = isHttps ? "HTTPS" : "HTTP";
    protoEl.style.color = isHttps
      ? "var(--cyan, #00E5BF)"
      : "var(--warning, #F5A623)";
    protoEl.dataset.fromTab = "1";
  }

  // --- Read analysis result stored on window by content.js ---
  chrome.scripting.executeScript(
    {
      target: { tabId: tab.id },
      func: () => window.shadowLinkData || null,
    },
    (results) => {
      if (chrome.runtime.lastError) {
        // executeScript fails on restricted pages (chrome://, PDF, etc.)
        console.warn(
          "[ShadowLink Popup] executeScript error:",
          chrome.runtime.lastError.message,
        );
        applyThreatStyling("Safe", 0);
        renderBreakdown([]);
        return;
      }

      const data = results?.[0]?.result;

      if (data) {
        applyThreatStyling(data.threatLevel, data.score);
        renderBreakdown(data.breakdown);
        renderVTStats(data.vtStats, data.domainAgeDays);
      } else {
        // Content script hasn't finished yet or the page is restricted
        applyThreatStyling("Safe", 0);
        renderBreakdown([]);
      }

      // Refine protocol display from content script's window.location.protocol
      // (more accurate than tab.url for pages with bad/self-signed certificates)
      if (data?.protocol && protoEl) {
        const isHttps = data.protocol === "https:";
        protoEl.textContent = isHttps ? "HTTPS" : "HTTP";
        protoEl.style.color = isHttps
          ? "var(--cyan, #00E5BF)"
          : "var(--warning, #F5A623)";
        delete protoEl.dataset.fromTab;
      }
    },
  );
});

// --- Load persisted screenshots and history from storage ---
chrome.storage.local.get(
  ["shadowlinkScreenshots", "shadowlinkHistory"],
  (data) => {
    renderScreenshots(data.shadowlinkScreenshots || []);
    renderHistory(data.shadowlinkHistory || []);
  },
);

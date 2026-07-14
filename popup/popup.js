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

  Safe: {
    color: "#00F5D4",
    label: "No threats detected"
  },

  Suspicious: {
    color: "#FACC15",
    label: "Suspicious activity detected"
  },

  Critical: {
    color: "#F97316",
    label: "Critical threat detected"
  },

  Dangerous: {
    color: "#EF4444",
    label: "Dangerous — do not proceed"
  }

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
    const riskPercent =
    Math.min(
        Math.round((score / 150) * 100),
        100
    );

scoreEl.textContent =
    `${riskPercent}%`;
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
      let displayUrl = item.url || "";
      try {
        const u = new URL(item.url);
        displayUrl = u.hostname + u.pathname.substring(0, 28);
      } catch {
        displayUrl = item.url.substring(0, 40);
      }

      return `
        <div class="evidence-item">
          <img class="evidence-thumb" src="${item.screenshot}" alt="Evidence screenshot" />
          <div class="evidence-info">
            <div class="evidence-url" title="${item.url}">${displayUrl}</div>
            <div class="evidence-time">${item.timestamp}</div>
          </div>
        </div>`;
    })
    .join("");
}

// =============================================================================
// THREAT HISTORY RENDERER
// =============================================================================

/** Colour map for threat level badges in the history list */
const HISTORY_COLORS = {
  Safe: "#00F5D4",
  Suspicious: "#FACC15",
  Critical: "#F97316",
  Dangerous: "#EF4444"
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
// THREAT TIMELINE RENDERER
// =============================================================================

/**
 * renderTimeline(timeline)
 * @param {{ id: number, threatLevel: string, score: number, url: string,
 *           hostname: string, category: string, timestamp: string }[]} timeline
 */
function renderTimeline(timeline) {
  const container = document.getElementById("timeline");
  if (!container) return;

  if (!timeline || timeline.length === 0) {
    container.innerHTML = `
      <div class="empty-state">
        <div class="empty-icon">📡</div>
        <div>No threats recorded</div>
      </div>`;
    return;
  }

  const levelClass = {
  Suspicious: "suspicious",
  Critical: "critical",
  Dangerous: "dangerous",
  Safe: "safe"
};

  container.innerHTML = timeline
    .map((item, idx) => {
      const cls = levelClass[item.threatLevel] || "warning";
      let displayHost = item.hostname || item.url || "";
      if (displayHost.length > 35)
        displayHost = displayHost.substring(0, 32) + "…";
      const isLast = idx === timeline.length - 1;

      return `
      <div class="timeline-item">
        <div class="timeline-dot-col">
          <div class="timeline-dot ${cls}"></div>
          ${!isLast ? '<div class="timeline-line"></div>' : ""}
        </div>
        <div class="timeline-content">
          <div class="timeline-header">
            <span class="timeline-category">${item.category || item.threatLevel}</span>
            <span class="timeline-score">+${item.score}</span>
          </div>
          <div class="timeline-url" title="${item.url}">${displayHost}</div>
          <div class="timeline-time">${item.timestamp}</div>
          <span class="timeline-badge ${cls}">${item.threatLevel}</span>
        </div>
      </div>`;
    })
    .join("");
}

// =============================================================================
// MAIN INIT — runs when popup.html finishes loading
// =============================================================================

// Show scanning state immediately while data loads
const breakdownEl = document.getElementById("breakdown");
if (breakdownEl) {
  breakdownEl.innerHTML = `<div class="scanning-msg"><span class="scanning-dot"></span><span class="scanning-dot"></span><span class="scanning-dot"></span></div>`;
}

chrome.tabs.query(
    {
        active: true,
        currentWindow: true
    },
    (tabs) => {

        const tab = tabs[0];

        if (!tab) return;

        /*
        |--------------------------------------------------------------------------
        | REAL URL EXTRACTION
        |--------------------------------------------------------------------------
        */

        let analyzedUrl =
    tab.url || "";

        let warningBreakdown = [];

        /*
        |--------------------------------------------------------------------------
        | If user is on ShadowLink warning page,
        | extract ORIGINAL malicious URL
        |--------------------------------------------------------------------------
        */

        if (
            analyzedUrl.includes(
                "/warning/warning.html"
            )
        ) {
            try {

                const parsed =
                    new URL(analyzedUrl);

                /*
                |--------------------------------------------------------------------------
                | Real blocked URL
                |--------------------------------------------------------------------------
                */

                const realUrl =
                    parsed.searchParams.get(
                        "url"
                    );

                if (realUrl) {
                    analyzedUrl =
                        decodeURIComponent(
                            realUrl
                        );
                }

                /*
                |--------------------------------------------------------------------------
                | Extract indicators from warning page
                |--------------------------------------------------------------------------
                */

                const reasonParam =
                    parsed.searchParams.get(
                        "reason"
                    );

                if (reasonParam) {

                    warningBreakdown =
                        reasonParam
                            .split("|")
                            .map((r) => r.trim())
                            .filter(Boolean)
                            .map((reason) => ({
                                reason,
                                points: 25
                            }));
                }

            } catch (err) {

                console.warn(
                    "[ShadowLink] Warning parse failed:",
                    err
                );
            }
        }

        console.log(
            "[ShadowLink] Final analyzed URL:",
            analyzedUrl
        );

  function setProtocolBadge(isHttps) {
    const el = document.getElementById("protocol");
    if (!el) return;
    el.textContent = isHttps ? "HTTPS" : "HTTP";
    el.classList.remove("https", "http");
    el.classList.add(isHttps ? "https" : "http");
    el.style.color = isHttps ? "var(--cyan, #00E5BF)" : "var(--warning, #F5A623)";
  }

  // --- Display the current site URL (truncated) ---
  const siteEl = document.getElementById("site");
  if (siteEl) {
    try {
      const parsed = new URL(analyzedUrl);
      siteEl.textContent = parsed.hostname + parsed.pathname.substring(0, 30);
    } catch {
      siteEl.textContent = analyzedUrl.substring(0, 50);
    }
  }

  setProtocolBadge(analyzedUrl.startsWith("https"));

  // --- Read analysis result stored on window by content.js ---
  chrome.scripting.executeScript(
    {
      target: { tabId: tab.id },
      func: () => window.shadowLinkData || null,
    },
    (results) => {
      if (chrome.runtime.lastError) {

    console.warn(
        "[ShadowLink Popup] executeScript error:",
        chrome.runtime.lastError.message,
    );

    if (tab.url && tab.url.includes("/warning/warning.html")) {
      applyThreatStyling("Dangerous", 75);
      renderBreakdown(warningBreakdown.length ? warningBreakdown : [{ points: 75, reason: "Malicious page blocked by ShadowLink" }]);
      renderVTStats(null, null);
      return;
    }

    applyThreatStyling("Safe", 0);
    renderBreakdown([]);
    return;
  }

  let data = results?.[0]?.result;

  if (tab.url && tab.url.includes("/warning/warning.html")) {
    const ws = warningBreakdown.length > 0 ? Math.max(warningBreakdown.reduce((s, i) => s + i.points, 0), 75) : 75;
    data = {
      score: ws,
      threatLevel: ws >= 90 ? "Dangerous" : ws >= 60 ? "Critical" : ws >= 25 ? "Suspicious" : "Safe",
      breakdown: warningBreakdown.length > 0 ? warningBreakdown : [{ points: ws, reason: "Malicious page blocked by ShadowLink" }],
      vtStats: null,
      domainAgeDays: null
    };
  }

      if (data) {
        let finalBreakdown =
    data.breakdown || [];

if (warningBreakdown.length > 0) {
    finalBreakdown =
        warningBreakdown;
}

applyThreatStyling(
    data.threatLevel,
    data.score
);

renderBreakdown(
    finalBreakdown
);

renderVTStats(
    data.vtStats,
    data.domainAgeDays
);

if (data.vtPending) {
  const pollTimer = setInterval(() => {
    chrome.scripting.executeScript({
      target: { tabId: tab.id },
      func: () => window.shadowLinkData || null,
    }, (pollResults) => {
      const updated = pollResults?.[0]?.result;
      if (updated && !updated.vtPending) {
        applyThreatStyling(updated.threatLevel, updated.score);
        renderBreakdown(updated.breakdown || []);
        renderVTStats(updated.vtStats, updated.domainAgeDays);
        clearInterval(pollTimer);
      }
    });
  }, 500);
  setTimeout(() => clearInterval(pollTimer), 15000);
}
      } else {
        // Content script didn't run (DNS error, blocked page, etc.)
        // Run a lightweight URL-only analysis from the popup side
        try {
          const tabUrl = analyzedUrl;
          const hostname = new URL(tabUrl).hostname
            .toLowerCase()
            .replace(/^www\./, "");
          const label = hostname.split(".")[0];

          // Quick homoglyph check inline
          const brands = [
            "google",
            "paypal",
            "microsoft",
            "facebook",
            "apple",
            "amazon",
            "instagram",
            "netflix",
            "twitter",
            "linkedin",
            "github",
          ];

          function qNorm(s) {
            return s
              .toLowerCase()
              .replace(/0/g, "o")
              .replace(/1/g, "l")
              .replace(/3/g, "e")
              .replace(/5/g, "s");
          }

          let fallbackScore = 0;
          const fallbackBreakdown = [];

          if (tabUrl.startsWith("http://")) {
            fallbackScore += 15;
            fallbackBreakdown.push({
              points: 15,
              reason: "Unencrypted connection (HTTP)",
            });
          }

          const normLabel = qNorm(label);
          for (const brand of brands) {
            const normBrand = qNorm(brand);
            if (normLabel === normBrand) continue;
            if (
              hostname === brand + ".com" ||
              hostname.endsWith("." + brand + ".com")
            )
              continue;
            const dist = levenshtein(normLabel, normBrand);
            const maxD = Math.min(Math.floor(normBrand.length * 0.25), 2);
            if (dist >= 1 && dist <= maxD) {
              fallbackScore += 60;
              fallbackBreakdown.push({
                points: 60,
                reason: `Possible homoglyph attack targeting: ${brand} (detected: ${label})`,
              });
              break;
            }
          }

          const suspTLDs = [
            ".xyz",
            ".top",
            ".click",
            ".tk",
            ".gq",
            ".ml",
            ".cf",
            ".ga",
            ".work",
            ".buzz",
          ];
          for (const tld of suspTLDs) {
            if (hostname.endsWith(tld)) {
              fallbackScore += 20;
              fallbackBreakdown.push({
                points: 20,
                reason: `Suspicious TLD: ${tld}`,
              });
              break;
            }
          }

          let fallbackLevel = "Safe";
          if (fallbackScore >= 100) fallbackLevel = "Dangerous";
          else if (fallbackScore >= 60) fallbackLevel = "Suspicious";
          else if (fallbackScore >= 30) fallbackLevel = "Warning";

          applyThreatStyling(fallbackLevel, fallbackScore);
          renderBreakdown(fallbackBreakdown);

          // Update icon
          if (fallbackLevel !== "Safe") {
            const iconMap = { Suspicious: "yellow", Warning: "orange", Dangerous: "red" };
            chrome.action.setIcon({
              path: { 128: `../assets/icons/${iconMap[fallbackLevel]}.png` },
              tabId: tab.id,
            });
          }
        } catch {
          applyThreatStyling("Safe", 0);
          renderBreakdown([]);
        }
      }

      if (data?.protocol) {
        setProtocolBadge(data.protocol === "https:");
      }

      // Capture screenshot popup-side (popup always has activeTab permission,
      // unlike the background service worker which never has it for these events).
      if (data && (data.threatLevel === "Dangerous" || data.threatLevel === "Critical")) {
        (async () => {
          try {
            const shot = await chrome.tabs.captureVisibleTab({ format: "png" });
            const { shadowlinkScreenshots } = await chrome.storage.local.get(["shadowlinkScreenshots"]);
            const list = shadowlinkScreenshots || [];
            list.unshift({
              url: analyzedUrl,
              timestamp: new Date().toLocaleString(),
              timestampRaw: Date.now(),
              screenshot: shot
            });
            await chrome.storage.local.set({ shadowlinkScreenshots: list.slice(0, 10) });
            // Re-render so the popup shows the captured evidence immediately
            const { shadowlinkScreenshots: updated } = await chrome.storage.local.get(["shadowlinkScreenshots"]);
            renderScreenshots(updated || []);
          } catch (e) {
            console.warn("[ShadowLink] Popup screenshot capture failed:", e);
          }
        })();
      }
    },
  );
});

// --- Load persisted screenshots and history from storage ---
chrome.storage.local.get(
  ["shadowlinkScreenshots", "shadowlinkHistory", "shadowlinkTimeline"],
  (data) => {
    renderScreenshots(data.shadowlinkScreenshots || []);
    renderHistory(data.shadowlinkHistory || []);
    renderTimeline(data.shadowlinkTimeline || []);
  },
);

// Clear timeline button
const clearBtn = document.getElementById("clearTimeline");
if (clearBtn) {
  clearBtn.addEventListener("click", () => {
    chrome.storage.local.remove(["shadowlinkTimeline"], () => {
      renderTimeline([]);
    });
  });
}


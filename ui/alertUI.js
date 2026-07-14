/* ==========================================================================
   ShadowLink — alertUI.js
   Floating Threat Card — cinematic glassmorphism popup
   ========================================================================== */

const SEVERITY = {
  Safe: {
    color: "var(--safe)",
    glow: "rgba(0,229,191,0.3)",
    icon: "🛡️",
    label: "SECURE",
  },
  Warning: {
    color: "var(--warning)",
    glow: "rgba(245,166,35,0.3)",
    icon: "⚠️",
    label: "WARNING",
  },
  Suspicious: {
    color: "var(--suspicious)",
    glow: "rgba(255,107,53,0.35)",
    icon: "🔍",
    label: "SUSPICIOUS",
  },
  Critical: {
    color: "var(--suspicious)",
    glow: "rgba(249,115,22,0.35)",
    icon: "⚠️",
    label: "CRITICAL",
  },
  Dangerous: {
    color: "var(--dangerous)",
    glow: "rgba(255,59,59,0.4)",
    icon: "☠️",
    label: "DANGEROUS",
  },
};

/* --------------------------------------------------------------------------
   injectStyles — inject all keyframes once, guarded by id
   -------------------------------------------------------------------------- */
function injectStyles() {
  if (document.getElementById("shadowlink-styles")) return;

  const style = document.createElement("style");
  style.id = "shadowlink-styles";
  style.textContent = `
    @keyframes shadowlinkEntry {
      from { transform: translateX(120%) scale(0.95); opacity: 0; }
      to   { transform: translateX(0)    scale(1);    opacity: 1; }
    }
    @keyframes shadowlinkExit {
      from { transform: translateX(0)    scale(1);    opacity: 1; }
      to   { transform: translateX(120%) scale(0.95); opacity: 0; }
    }
    @keyframes shadowlinkRing {
      0%, 100% { transform: scale(1);    opacity: 0.6; }
      50%      { transform: scale(1.18); opacity: 1;   }
    }
    @keyframes shadowlinkShake {
      0%,  100% { transform: translateX(0);   }
      20%        { transform: translateX(-5px); }
      40%        { transform: translateX(5px);  }
      60%        { transform: translateX(-3px); }
      80%        { transform: translateX(3px);  }
    }
    #shadowlink-popup * {
      box-sizing: border-box;
    }
    #shadowlink-popup .sl-close-btn:hover {
      background: rgba(255,255,255,0.1) !important;
    }
    #shadowlink-popup .sl-dismiss-btn:hover {
      filter: brightness(1.15);
    }
  `;
  document.head.appendChild(style);
}

/* --------------------------------------------------------------------------
   dismissPopup — exit animation then DOM removal
   -------------------------------------------------------------------------- */
function dismissPopup(popup) {
  popup.style.animation = "shadowlinkExit 0.3s ease forwards";
  setTimeout(() => {
    if (popup && popup.parentNode) popup.remove();
  }, 300);
}

/* --------------------------------------------------------------------------
   showThreatPopup — main exported global
   -------------------------------------------------------------------------- */
function showThreatPopup(result) {
  injectStyles();

  /* ── Resolve severity config ──────────────────────────────────────────── */
  const cfg = SEVERITY[result.threatLevel] || SEVERITY.Warning;

  /* ── Clamp values ─────────────────────────────────────────────────────── */
  const displayScore = Math.min(result.score, 999);
  const barWidthPct = Math.min((result.score / 150) * 100, 100).toFixed(1);
  const hasIndicators =
    Array.isArray(result.indicators) && result.indicators.length > 0;

  /* ── Upsert: update existing popup rather than spawning duplicates ─────── */
  let popup = document.getElementById("shadowlink-popup");
  const isNew = !popup;

  if (isNew) {
    popup = document.createElement("div");
    popup.id = "shadowlink-popup";
  }

  /* ── Container styles ─────────────────────────────────────────────────── */
  popup.style.cssText = `
    position:               fixed;
    top:                    24px;
    right:                  24px;
    width:                  360px;
    background:             rgba(7,11,26,0.92);
    backdrop-filter:        blur(24px);
    -webkit-backdrop-filter:blur(24px);
    border:                 1.5px solid ${cfg.color};
    border-radius:          20px;
    padding:                22px 22px 18px;
    z-index:                2147483647;
    color:                  #F0F6FF;
    font-family:            'Inter', Arial, sans-serif;
    box-shadow:             0 0 0 1px rgba(255,255,255,0.04),
                            0 8px 32px rgba(0,0,0,0.6),
                            0 0 40px ${cfg.glow};
    animation:              shadowlinkEntry 0.4s cubic-bezier(0.16,1,0.3,1) forwards;
    overflow:               hidden;
  `;

  /* ── Indicator rows HTML ──────────────────────────────────────────────── */
  const indicatorsHTML = hasIndicators
    ? `
    <div style="margin-top:16px;">
      <div style="
        font-size:10px;
        letter-spacing:0.12em;
        text-transform:uppercase;
        color:rgba(240,246,255,0.4);
        margin-bottom:8px;
        font-weight:600;
      ">Threat Indicators</div>
      <ul style="
        list-style:none;
        margin:0;
        padding:0;
        display:flex;
        flex-direction:column;
        gap:5px;
      ">
        ${result.indicators
          .map(
            (ind) => `
          <li style="
            display:flex;
            align-items:flex-start;
            gap:8px;
            font-size:12px;
            color:rgba(240,246,255,0.75);
            line-height:1.4;
          ">
            <span style="
              flex-shrink:0;
              width:6px;
              height:6px;
              border-radius:50%;
              background:${cfg.color};
              margin-top:4px;
              box-shadow: 0 0 6px ${cfg.glow};
            "></span>
            <span>${ind}</span>
          </li>
        `,
          )
          .join("")}
      </ul>
    </div>
  `
    : "";

  /* ── Inner HTML ───────────────────────────────────────────────────────── */
  popup.innerHTML = `

    <!-- Close button -->
    <button class="sl-close-btn" style="
      position:        absolute;
      top:             12px;
      right:           12px;
      background:      none;
      border:          none;
      color:           rgba(240,246,255,0.5);
      font-size:       18px;
      line-height:     1;
      cursor:          pointer;
      padding:         4px 6px;
      border-radius:   6px;
      transition:      background 0.15s ease, color 0.15s ease;
      z-index:         1;
    ">✕</button>

    <!-- Header row -->
    <div style="
      display:      flex;
      align-items:  center;
      gap:          14px;
      margin-right: 28px;
    ">

      <!-- Animated shield ring -->
      <div style="
        position:    relative;
        flex-shrink: 0;
        width:       52px;
        height:      52px;
        display:     flex;
        align-items: center;
        justify-content: center;
      ">
        <!-- Pulsing ring -->
        <div style="
          position:      absolute;
          inset:         0;
          border-radius: 50%;
          border:        2px solid ${cfg.color};
          opacity:       0.6;
          animation:     shadowlinkRing 2s ease-in-out infinite;
        "></div>
        <!-- Outer glow ring -->
        <div style="
          position:      absolute;
          inset:         -6px;
          border-radius: 50%;
          border:        1px solid ${cfg.color};
          opacity:       0.2;
          animation:     shadowlinkRing 2s ease-in-out infinite 0.4s;
        "></div>
        <!-- Icon -->
        <span style="
          font-size:  28px;
          line-height: 1;
          position:   relative;
          z-index:    1;
        ">${cfg.icon}</span>
      </div>

      <!-- Header text -->
      <div style="flex:1;min-width:0;">
        <!-- Brand row -->
        <div style="
          display:     flex;
          align-items: center;
          gap:         6px;
          margin-bottom:5px;
        ">
          <span style="
            font-size:   12px;
            font-weight: 700;
            color:       #F0F6FF;
            letter-spacing: 0.04em;
          ">ShadowLink</span>
          <span style="color:rgba(240,246,255,0.25);font-size:10px;">·</span>
          <span style="
            font-size:  10px;
            color:      rgba(240,246,255,0.4);
            letter-spacing: 0.04em;
          ">Threat Intelligence Framework</span>
        </div>
        <!-- Threat level badge -->
        <div style="
          font-family:     'JetBrains Mono', 'Fira Code', 'Consolas', monospace;
          font-size:       22px;
          font-weight:     700;
          color:           ${cfg.color};
          letter-spacing:  0.06em;
          text-transform:  uppercase;
          line-height:     1;
          text-shadow:     0 0 20px ${cfg.glow};
        ">${cfg.label}</div>
      </div>
    </div>

    <!-- Score bar section -->
    <div style="margin-top:18px;">
      <div style="
        display:         flex;
        justify-content: space-between;
        align-items:     center;
        margin-bottom:   7px;
      ">
        <span style="
          font-size:       10px;
          letter-spacing:  0.12em;
          text-transform:  uppercase;
          color:           rgba(240,246,255,0.4);
          font-weight:     600;
        ">Risk Score</span>
        <span style="
          font-family:  'JetBrains Mono', 'Consolas', monospace;
          font-size:    13px;
          font-weight:  700;
          color:        ${cfg.color};
        ">${displayScore}</span>
      </div>
      <!-- Track -->
      <div style="
        width:         100%;
        height:        6px;
        background:    rgba(255,255,255,0.08);
        border-radius: 9999px;
        overflow:      hidden;
      ">
        <!-- Fill — width animated via inline style override after mount -->
        <div id="sl-score-fill" style="
          height:        100%;
          width:         0%;
          background:    ${cfg.color};
          border-radius: 9999px;
          box-shadow:    0 0 8px ${cfg.glow};
          transition:    width 0.8s ease;
        "></div>
      </div>
    </div>

    <!-- Indicators -->
    ${indicatorsHTML}

    <!-- Footer row -->
    <div style="
      display:         flex;
      justify-content: space-between;
      align-items:     center;
      margin-top:      18px;
      padding-top:     14px;
      border-top:      1px solid rgba(255,255,255,0.07);
    ">
      <span style="
        font-size:  10px;
        color:      rgba(240,246,255,0.3);
        letter-spacing: 0.03em;
      ">Powered by ShadowLink Threat Intelligence</span>

      <button class="sl-dismiss-btn" style="
        background:    ${cfg.color};
        border:        none;
        color:         #02040F;
        font-size:     12px;
        font-weight:   700;
        letter-spacing:0.04em;
        padding:       6px 16px;
        border-radius: 9999px;
        cursor:        pointer;
        transition:    filter 0.15s ease;
        font-family:   'Inter', Arial, sans-serif;
      ">Dismiss</button>
    </div>
  `;

  /* ── Mount ────────────────────────────────────────────────────────────── */
  if (isNew) {
    document.body.appendChild(popup);
  }

  /* ── Animate score bar fill (deferred so transition fires) ───────────── */
  requestAnimationFrame(() => {
    requestAnimationFrame(() => {
      const fill = document.getElementById("sl-score-fill");
      if (fill) fill.style.width = `${barWidthPct}%`;
    });
  });

  /* ── Shake on Dangerous (fires after entry animation ~400ms) ─────────── */
  if (result.threatLevel === "Dangerous") {
    setTimeout(() => {
      if (!popup.parentNode) return;
      popup.style.animation = "shadowlinkShake 0.3s ease 2";
      // Restore normal state after shake
      setTimeout(() => {
        if (popup.parentNode) popup.style.animation = "none";
      }, 620);
    }, 450);
  }

  /* ── Auto-dismiss timers ─────────────────────────────────────────────── */
  let autoTimer = null;

  if (result.threatLevel === "Suspicious") {
    autoTimer = setTimeout(() => dismissPopup(popup), 10000);
  } else if (result.threatLevel === "Dangerous") {
    autoTimer = setTimeout(() => dismissPopup(popup), 12000);
  }

  /* ── Wire up close / dismiss buttons ────────────────────────────────── */
  const clearAndDismiss = () => {
    if (autoTimer) clearTimeout(autoTimer);
    dismissPopup(popup);
  };

  popup
    .querySelector(".sl-close-btn")
    .addEventListener("click", clearAndDismiss);
  popup
    .querySelector(".sl-dismiss-btn")
    .addEventListener("click", clearAndDismiss);
}

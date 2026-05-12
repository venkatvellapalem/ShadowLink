/* ==========================================================================
   ShadowLink — warningBanner.js
   Minimal Floating Shield Widget — Live Threat Status Indicator
   ========================================================================== */

function showWarningBanner(result) {
  /* ── Remove any existing banner first ─────────────────────────────────── */
  const existing = document.getElementById("shadowlink-banner");
  if (existing) existing.remove();

  /* ── Only render for non-safe threat levels ────────────────────────────── */
  if (!result || result.threatLevel === "Safe") return;

  /* ── Severity colour map ───────────────────────────────────────────────── */
  const COLORS = {
    Warning: {
      color: "#F59E0B",
      glow: "rgba(245,158,11,0.25)",
    },
    Caution: {
      color: "#F59E0B",
      glow: "rgba(245,158,11,0.25)",
    },
    Suspicious: {
      color: "#F97316",
      glow: "rgba(249,115,22,0.3)",
    },
    Dangerous: {
      color: "#EF4444",
      glow: "rgba(239,68,68,0.35)",
    },
  };

  const cfg = COLORS[result.threatLevel] || COLORS.Caution;

  /* ── Inject keyframes once, guarded by id ──────────────────────────────── */
  if (!document.getElementById("sl-banner-styles")) {
    const style = document.createElement("style");
    style.id = "sl-banner-styles";
    style.textContent = `
      @keyframes slBannerIn {
        from { transform: translateY(20px); opacity: 0; }
        to   { transform: translateY(0);    opacity: 1; }
      }
      #shadowlink-banner:hover {
        transform: translateY(-2px) !important;
      }
    `;
    document.head.appendChild(style);
  }

  /* ── Create widget element ─────────────────────────────────────────────── */
  const widget = document.createElement("div");
  widget.id = "shadowlink-banner";

  widget.style.cssText = `
    position:                fixed;
    bottom:                  20px;
    right:                   20px;
    background:              rgba(7,11,26,0.9);
    backdrop-filter:         blur(20px);
    -webkit-backdrop-filter: blur(20px);
    border:                  1.5px solid ${cfg.color};
    border-radius:           14px;
    padding:                 12px 16px;
    z-index:                 2147483646;
    color:                   white;
    font-family:             'Inter', Arial, sans-serif;
    font-size:               13px;
    box-shadow:              0 0 24px ${cfg.glow},
                             0 4px 16px rgba(0,0,0,0.5);
    display:                 flex;
    align-items:             center;
    gap:                     10px;
    cursor:                  pointer;
    transition:              transform 0.2s ease;
    animation:               slBannerIn 0.3s cubic-bezier(0.16,1,0.3,1) forwards;
    user-select:             none;
  `;

  /* ── Widget inner markup ───────────────────────────────────────────────── */
  widget.innerHTML = `
    <span style="font-size:18px;line-height:1;flex-shrink:0;">🛡️</span>

    <div style="flex:1;min-width:0;">
      <div style="
        font-weight:    700;
        color:          ${cfg.color};
        font-size:      13px;
        letter-spacing: 0.05em;
        text-transform: uppercase;
        line-height:    1.2;
      ">${result.threatLevel}</div>
      <div style="
        font-size:   11px;
        opacity:     0.5;
        margin-top:  2px;
        line-height: 1.2;
      ">ShadowLink Detection</div>
    </div>

    <span style="
      flex-shrink: 0;
      margin-left: 4px;
      opacity:     0.35;
      font-size:   15px;
      line-height: 1;
      transition:  opacity 0.15s ease;
    ">✕</span>
  `;

  /* ── Dismiss on click — slide down and fade out ────────────────────────── */
  widget.addEventListener("click", () => {
    widget.style.transition = "transform 0.3s ease, opacity 0.3s ease";
    widget.style.transform = "translateY(20px)";
    widget.style.opacity = "0";
    setTimeout(() => {
      if (widget.parentNode) widget.remove();
    }, 300);
  });

  /* ── Mount ─────────────────────────────────────────────────────────────── */
  document.body.appendChild(widget);
}

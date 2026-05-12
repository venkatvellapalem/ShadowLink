/* ==========================================================================
   ShadowLink — warning.js
   Full-Page Threat Warning — Runtime Logic
   ========================================================================== */

(function () {
  "use strict";

  /* ── Parse URL query parameters ────────────────────────────────────────── */
  const params = new URLSearchParams(window.location.search);
  const reason = params.get("reason") || "";
  const url = params.get("url") || "Unknown URL";

  /* ── Display the blocked URL in the reason box ─────────────────────────── */
  const blockedUrlEl = document.getElementById("blockedUrl");
  if (blockedUrlEl) {
    blockedUrlEl.textContent = url;
  }

  /* ── Parse pipe-delimited indicators and render the list ───────────────── */
  const listEl = document.getElementById("indicatorList");
  if (listEl && reason) {
    const indicators = reason
      .split(" | ")
      .map((s) => s.trim())
      .filter(Boolean);

    if (indicators.length > 0) {
      listEl.innerHTML = indicators
        .map((indicator) => `<li>${escapeHTML(indicator)}</li>`)
        .join("");
    }
  }

  /* ── Back button — return to previous safe page ────────────────────────── */
  const backBtn = document.getElementById("backBtn");
  if (backBtn) {
    backBtn.addEventListener("click", () => {
      if (history.length > 1) {
        history.back();
      } else {
        window.close();
      }
    });
  }

  /* ── Proceed button — navigate to the original (blocked) URL ───────────── */
  const proceedBtn = document.getElementById("proceedBtn");
  if (proceedBtn) {
    proceedBtn.addEventListener("click", () => {
      const target = params.get("url");
      if (target) {
        // Navigate directly, bypassing the ShadowLink block
        window.location.href = target;
      }
    });
  }

  /* ── Utility: basic HTML escaping to prevent XSS in indicators ─────────── */
  function escapeHTML(str) {
    return str
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#039;");
  }
})();

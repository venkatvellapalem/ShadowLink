/**
 * loginDetector.js — ShadowLink Phishing Detection
 *
 * Scans the live DOM for password-bearing login forms on untrusted domains.
 * Key improvements over the previous version:
 *
 *   1. Trusted-domain check uses EXACT hostname matching (endsWith) rather
 *      than a loose .includes(), which would incorrectly trust any hostname
 *      that merely contains a brand name (e.g. "notpaypal-secure.com").
 *
 *   2. Each indicator message is only added once — the old version pushed
 *      a "Password input field detected" string for every form element,
 *      causing duplicate entries in the threat breakdown.
 *
 *   3. Returns early (empty array) on trusted domains so no processing
 *      overhead is wasted on legitimate login pages (google.com, github.com…).
 *
 * Depends on (loaded before this file per manifest.json):
 *   constants.js → trustedDomains
 */

/* global trustedDomains */

// ---------------------------------------------------------------------------
// detectLoginForms()
//
// Runs in content-script context (has access to document / window).
// @returns {string[]} — Array of indicator strings, empty if no threat found.
// ---------------------------------------------------------------------------
function detectLoginForms() {
  const indicators = [];

  try {
    // Strip leading "www." for a clean second-level domain comparison
    const hostname = window.location.hostname
      .replace(/^www\./, "")
      .toLowerCase();

    // ----- Trusted-domain guard -------------------------------------------
    // Use the global trustedDomains list; fall back to an empty array if the
    // constants file failed to load for any reason.
    const trusted = typeof trustedDomains !== "undefined" ? trustedDomains : [];

    // A domain is considered trusted when the current hostname IS the brand
    // domain OR is an official subdomain of it.
    //   hostname === 'paypal.com'         → trusted
    //   hostname === 'accounts.google.com' → trusted (endsWith '.google.com')
    //   hostname === 'notpaypal.com'       → NOT trusted (.includes would fail here)
    const isTrusted = trusted.some(
      (brand) =>
        hostname === `${brand}.com` ||
        hostname === `${brand}.net` ||
        hostname === `${brand}.org` ||
        hostname === `${brand}.io` ||
        hostname.endsWith(`.${brand}.com`) ||
        hostname.endsWith(`.${brand}.net`) ||
        hostname.endsWith(`.${brand}.org`) ||
        hostname.endsWith(`.${brand}.io`),
    );

    // Trusted sites are always skipped — no need to evaluate further
    if (isTrusted) return [];

    // ----- Password field detection ----------------------------------------
    const passwordInputs = document.querySelectorAll('input[type="password"]');

    // No password inputs → nothing to flag
    if (passwordInputs.length === 0) return [];

    // At this point we know: untrusted domain + has a password input
    indicators.push(
      "Login form with password field detected on untrusted domain",
    );

    // ----- Suspicious form action detection --------------------------------
    // Forms that collect credentials but submit to "#", an empty action, or
    // a relative path with no real destination are a strong phishing signal
    // (the page likely uses JS to exfiltrate data instead).
    const forms = document.querySelectorAll("form");
    let foundSuspiciousAction = false;

    forms.forEach((form) => {
      if (foundSuspiciousAction) return; // Only report once

      const hasPassword = form.querySelector('input[type="password"]');
      if (!hasPassword) return;

      const action = (form.getAttribute("action") || "").trim();

      // Flag if action is absent, empty, or a bare hash anchor
      if (!action || action === "#") {
        foundSuspiciousAction = true;
      }
    });

    if (foundSuspiciousAction) {
      indicators.push(
        "Password form submits to an unknown or empty destination",
      );
    }

    // ----- Autocomplete-off detection -------------------------------------
    // Phishing kits frequently disable autocomplete to prevent browser-
    // managed credential filling, which would reveal the fake site.
    const hasAutocompleteOff = Array.from(passwordInputs).some(
      (input) =>
        (input.getAttribute("autocomplete") || "").toLowerCase() === "off",
    );

    if (hasAutocompleteOff) {
      indicators.push(
        "Password field has autocomplete disabled (common in phishing kits)",
      );
    }
  } catch {
    // Silent — never throw from a content script detection function
  }

  return indicators;
}

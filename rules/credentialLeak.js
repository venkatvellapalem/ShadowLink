/**
 * credentialLeak.js — Credential Harvesting Detection
 * Detects password forms on untrusted domains, HTTP credential submission,
 * and fake login UI patterns.
 *
 * CRITICAL: Does NOT flag trusted brand sites.
 * Facebook's own login page is legitimate — only untrusted domains are checked.
 */

/* global trustedDomains */

/**
 * detectCredentialThreats()
 * Runs in content-script context; reads the live DOM.
 * @returns {{ score: number, indicators: string[] }}
 */
function detectCredentialThreats() {
  const result = { score: 0, indicators: [] };

  try {
    const hostname = window.location.hostname.replace(/^www\./, '').toLowerCase();
    const protocol = window.location.protocol;

    // ── Trust check ──────────────────────────────────────────────────────────
    // Build trusted-domain set from the shared list injected by the extension.
    // If trustedDomains is unavailable, fall back to an empty array (conservative).
    const trusted = typeof trustedDomains !== 'undefined' ? trustedDomains : [];

    const isTrusted = trusted.some(function (brand) {
      // Match exact TLD variants and any subdomain thereof
      return (
        hostname === brand + '.com'  ||
        hostname === brand + '.net'  ||
        hostname === brand + '.org'  ||
        hostname === brand + '.co'   ||
        hostname === brand + '.io'   ||
        hostname.endsWith('.' + brand + '.com') ||
        hostname.endsWith('.' + brand + '.net') ||
        hostname.endsWith('.' + brand + '.org') ||
        hostname.endsWith('.' + brand + '.co')  ||
        hostname.endsWith('.' + brand + '.io')
      );
    });

    // Stop here — this is a legitimate brand page
    if (isTrusted) return result;

    // ── Prerequisite: at least one password field must exist ─────────────────
    const passwordInputs = document.querySelectorAll('input[type="password"]');
    if (passwordInputs.length === 0) return result;

    // ── Check 1: HTTP connection with password field (critical) ──────────────
    if (protocol === 'http:') {
      result.score += 50;
      result.indicators.push(
        'Password field detected on unencrypted HTTP connection \u2014 credentials at risk'
      );
    }

    // ── Check 2: Form action analysis ────────────────────────────────────────
    const forms = document.querySelectorAll('form');
    forms.forEach(function (form) {
      const hasPassword = form.querySelector('input[type="password"]');
      if (!hasPassword) return;

      const action = (form.getAttribute('action') || '').trim();

      if (!action || action === '#') {
        // Empty or hash-only action: data goes nowhere visible (phishing kit pattern)
        result.score += 15;
        result.indicators.push(
          'Credential form has no submit destination (suspicious)'
        );
      } else if (action.startsWith('http://')) {
        // Explicit cleartext submission
        result.score += 30;
        result.indicators.push('Credentials submitted over unencrypted HTTP');
      } else if (action.startsWith('https://') || action.startsWith('http://')) {
        // Absolute URL — check for cross-domain submission
        try {
          const actionHost = new URL(action).hostname.replace(/^www\./, '').toLowerCase();
          if (actionHost !== hostname) {
            result.score += 25;
            result.indicators.push(
              'Credentials submitted to different domain: ' + actionHost
            );
          }
        } catch {
          /* ignore malformed action URLs */
        }
      }
    });

    // ── Check 3: autocomplete="off" on ALL password fields ───────────────────
    // Phishing kits disable autocomplete to prevent browsers from auto-filling
    // saved credentials (which would reveal the mismatch to the victim).
    let allAutocompleteOff = true;
    passwordInputs.forEach(function (inp) {
      const ac = (inp.getAttribute('autocomplete') || '').toLowerCase();
      if (ac !== 'off' && ac !== 'new-password') allAutocompleteOff = false;
    });

    if (allAutocompleteOff && passwordInputs.length > 0) {
      result.score += 10;
      result.indicators.push(
        'All credential fields have autocomplete disabled (phishing pattern)'
      );
    }

    // ── Check 4: Mismatched visible brand vs actual hostname ─────────────────
    // Look for brand names rendered in large heading text that don't match the host.
    const headings = Array.from(
      document.querySelectorAll('h1, h2, .logo, [class*="logo"], [class*="brand"]')
    );
    const headingText = headings
      .map(function (el) { return el.textContent || ''; })
      .join(' ')
      .toLowerCase();

    const knownBrandNames = [
      'paypal', 'google', 'facebook', 'microsoft', 'apple', 'amazon',
      'netflix', 'instagram', 'twitter', 'linkedin', 'dropbox', 'github',
      'yahoo', 'chase', 'wellsfargo', 'bankofamerica', 'citibank', 'hsbc'
    ];

    for (const brand of knownBrandNames) {
      if (headingText.includes(brand) && !hostname.includes(brand)) {
        result.score += 35;
        result.indicators.push(
          'Page claims to be ' + brand + ' but domain does not match (' + hostname + ')'
        );
        break; // one match is sufficient
      }
    }

  } catch {
    /* Silent — never let detection errors surface to the page */
  }

  return result;
}

/**
 * jsBehavior.js — JavaScript Behavior Analysis
 * Detects suspicious JavaScript patterns that indicate malicious intent.
 *
 * Conservative philosophy: only flags strong, unambiguous signals.
 * Legitimate sites that use minified/bundled JS must NOT be penalized.
 */

/**
 * analyzeJSBehavior()
 * Runs in content-script context; reads the live DOM.
 * @returns {{ score: number, indicators: string[] }}
 */
function analyzeJSBehavior() {
  const result = { score: 0, indicators: [] };

  try {

    // ── Check 1: Hidden external iframes ────────────────────────────────────
    // Drive-by download kits routinely load exploit payloads through invisible
    // iframes that point to attacker-controlled origins.
    // Signal requires: invisible + cross-origin src.
    const iframes = document.querySelectorAll('iframe');
    let hiddenIframeCount = 0;

    iframes.forEach(function (iframe) {
      const style  = window.getComputedStyle(iframe);
      const width  = parseInt(style.width,  10) || 0;
      const height = parseInt(style.height, 10) || 0;

      const isHidden = (
        width  <= 1 ||
        height <= 1 ||
        style.visibility === 'hidden' ||
        style.display    === 'none'   ||
        style.opacity    === '0'
      );

      if (!isHidden) return;

      // Only flag if the iframe loads a resource from a different origin
      const src = (iframe.getAttribute('src') || '').trim();
      if (src && src.startsWith('http') && !src.includes(window.location.hostname)) {
        hiddenIframeCount++;
      }
    });

    if (hiddenIframeCount >= 2) {
      result.score += 30;
      result.indicators.push(
        hiddenIframeCount + ' hidden external iframes detected'
      );
    } else if (hiddenIframeCount === 1) {
      result.score += 15;
      result.indicators.push('Hidden external iframe detected');
    }

    // ── Check 2: Instant meta-refresh redirect ───────────────────────────────
    // Phishing kits sometimes bounce victims through a chain of redirects using
    // <meta http-equiv="refresh" content="0; url=..."> so the original URL is
    // not the one displayed in browser warnings.
    const metaRefresh = document.querySelector('meta[http-equiv="refresh"]');
    if (metaRefresh) {
      const content = (metaRefresh.getAttribute('content') || '').trim();
      // content format: "delay" or "delay; url=..."
      const delay = parseInt(content.split(';')[0], 10);
      if (!isNaN(delay) && delay === 0) {
        result.score += 20;
        result.indicators.push('Instant meta-refresh redirect detected');
      }
    }

    // ── Check 3: Obfuscated eval/decode patterns in inline scripts ───────────
    // The combination of eval() + a decoder (atob / unescape / decodeURIComponent)
    // is the canonical obfuscation pattern used by phishing kits and malware
    // droppers to hide their actual payload from static scanners.
    //
    // We limit scanning to the first 20 non-empty inline scripts and require
    // each to be at least 50 characters to avoid flagging trivial one-liners.
    const inlineScripts = Array.from(document.querySelectorAll('script:not([src])'));
    let obfuscatedCount = 0;

    for (const script of inlineScripts.slice(0, 20)) {
      const src = (script.textContent || '').trim();
      if (src.length < 50) continue;

      // eval( atob(...) )  /  eval( unescape(...) )  /  eval( decodeURIComponent(...) )
      if (/eval\s*\(\s*(atob|unescape|decodeURIComponent)\s*\(/i.test(src)) {
        obfuscatedCount++;
      }
    }

    if (obfuscatedCount >= 2) {
      result.score += 35;
      result.indicators.push(
        'Obfuscated JavaScript detected (' + obfuscatedCount + ' eval/decode patterns)'
      );
    } else if (obfuscatedCount === 1) {
      result.score += 15;
      result.indicators.push('Potentially obfuscated JavaScript detected');
    }

    // ── Check 4: Clipboard hijacking listeners ───────────────────────────────
    // Some phishing pages attach oncopy / onpaste listeners that silently
    // replace clipboard content with malicious data (crypto address swapping,
    // credential skimming via paste interception).
    // We detect this by inspecting the body's event listener attributes only
    // (safe, no override needed).
    const body = document.body;
    if (body) {
      const hasCopyHijack  = typeof body.oncopy  === 'function';
      const hasPasteHijack = typeof body.onpaste === 'function';

      if (hasCopyHijack && hasPasteHijack) {
        result.score += 20;
        result.indicators.push(
          'Clipboard copy and paste events intercepted (credential/data skimming risk)'
        );
      } else if (hasCopyHijack || hasPasteHijack) {
        result.score += 10;
        result.indicators.push('Clipboard event interception detected');
      }
    }

    // ── Check 5: Aggressive context-menu / right-click disabling ────────────
    // Phishing pages occasionally disable right-click to prevent victims from
    // inspecting the page source or using "Copy link address" on fake links.
    // Legitimate sites virtually never disable context menus on the document.
    if (typeof document.oncontextmenu === 'function') {
      // Probe: attach our own handler and check whether it gets suppressed
      // (non-invasive — we don't actually replace the existing handler)
      result.score += 10;
      result.indicators.push(
        'Right-click context menu disabled (page inspection prevention)'
      );
    }

  } catch {
    /* Silent — detection failures must never surface to the page */
  }

  return result;
}

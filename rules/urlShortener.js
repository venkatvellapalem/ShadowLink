/**
 * urlShortener.js — URL Shortener Detection
 * Detects known URL shorteners and warns about hidden destinations.
 */

const URL_SHORTENERS = new Set([
  // ── General-purpose shorteners ────────────────────────────────────────────
  'bit.ly',        // Bitly
  'tinyurl.com',   // TinyURL
  't.co',          // Twitter/X internal shortener
  'goo.gl',        // Google (deprecated but still seen in the wild)
  'ow.ly',         // Hootsuite
  'buff.ly',       // Buffer
  'rebrand.ly',    // Rebrandly
  'cutt.ly',       // Cutt.ly
  'is.gd',         // is.gd
  'shorturl.at',   // ShortURL
  'tiny.cc',       // Tiny.cc
  'tr.im',         // tr.im
  'cli.gs',        // cli.gs
  'url.ie',        // url.ie
  'snip.ly',       // Snip.ly (adds overlays)
  'bl.ink',        // Bl.ink
  'short.io',      // Short.io
  'hyperurl.co',   // HyperURL
  'rb.gy',         // Rb.gy
  'urlzs.com',     // URLzs
  'trib.al',       // Linktree/Tribal
  // ── Platform-branded shorteners ───────────────────────────────────────────
  'lnkd.in',       // LinkedIn
  'fb.me',         // Facebook
  'amzn.to',       // Amazon
  'youtu.be',      // YouTube
  // ── Additional commonly-abused shorteners ─────────────────────────────────
  'x.co',          // GoDaddy
  'soo.gd',        // soo.gd
  'fur.ly',        // Fur.ly
  'scrnch.me',     // Scrnch
  'vzturl.com',    // vzturl
  'qr.ae',         // QR.ae
  'v.gd',          // v.gd
  'clck.ru',       // Yandex.Clck (commonly abused in phishing)
  'vk.cc',         // VK (Russian social)
  'u.to',          // u.to
  't2m.io',        // T2M
  'shrtco.de',     // Shrtco
  'chilp.it',      // Chilp.it
  'zi.ma',         // zi.ma
  'da.gd',         // da.gd
  'surl.li',       // surl.li
  'gg.gg',         // gg.gg
  'mcaf.ee',       // McAfee Secure (ironically used in phishing)
  'adf.ly',        // Adfly (ad-injecting, high-risk)
  'bc.vc',         // bc.vc
  'tny.im',        // tny.im
  'qlink.me',      // qlink.me
  'shorturl.asia'  // ShortURL Asia
]);

/**
 * checkURLShortener(url)
 * @param {string} url
 * @returns {{ isShortened: boolean, score: number, indicators: string[], shortener: string|null }}
 */
function checkURLShortener(url) {
  const result = {
    isShortened: false,
    score: 0,
    indicators: [],
    shortener: null
  };

  try {
    const parsed = new URL(url);
    const hostname = parsed.hostname.toLowerCase().replace(/^www\./, '');

    if (URL_SHORTENERS.has(hostname)) {
      result.isShortened = true;
      result.shortener   = hostname;
      result.score      += 10;
      result.indicators.push(
        'Shortened URL detected via ' + hostname + ' \u2014 destination hidden'
      );
    }
  } catch {
    // Malformed URL — silently ignore
  }

  return result;
}

// =============================================================================
// ShadowLink — background.js
// Service Worker: message handler + pre-navigation threat scanner
// =============================================================================

importScripts('rules/homoglyph.js', 'rules/constants.js');

/* ==========================================================================
   MESSAGE HANDLER
   ========================================================================== */

chrome.runtime.onMessage.addListener((message, sender) => {

  if (message.type === "CAPTURE_THREAT") {
    setTimeout(() => {
      const tab = sender?.tab;
      if (!tab?.id) return;

      chrome.tabs.captureVisibleTab(tab.windowId, { format: "png" }, screenshotUrl => {
        if (chrome.runtime.lastError) return;

        chrome.storage.local.get(["shadowlinkScreenshots"], data => {
          const screenshots = data.shadowlinkScreenshots || [];

          const now = Date.now();
          const dup = screenshots.some(s =>
            s.url === (message.url || sender?.tab?.url) &&
            (now - new Date(s.timestampRaw || 0)) < 300000
          );
          if (dup) return;

          screenshots.unshift({
            url: message.url || sender?.tab?.url || "",
            timestamp: new Date().toLocaleString(),
            timestampRaw: now,
            screenshot: screenshotUrl
          });

          chrome.storage.local.set({
            shadowlinkScreenshots: screenshots.slice(0, 10)
          });
        });
      });
    }, 600);
    return;
  }

  if (message.type === "UPDATE_ICON" && message.level === "Scanning") {
    if (sender?.tab?.id) {
      chrome.action.setIcon({ tabId: sender.tab.id, path: { 16: "assets/icons/icon16.png", 32: "assets/icons/icon32.png", 48: "assets/icons/icon48.png", 128: "assets/icons/icon128.png" } });
    }
    return;
  }

  if (message.type === "SET_EXTENSION_ICON") {
    if (sender?.tab?.id) {
      chrome.action.setIcon({ path: message.iconPath, tabId: sender.tab.id });
    } else {
      chrome.action.setIcon({ path: message.iconPath });
    }
    return;
  }
});

/* ==========================================================================
   HELPERS
   ========================================================================== */

function bgExtractLabel(hostname) {
  return hostname.replace(/^www\./, "").toLowerCase().split(".")[0];
}

function bgIsBrandHost(hostname, brand) {
  const h = hostname.toLowerCase();
  return (
    h === `${brand}.com` ||
    h === `www.${brand}.com` ||
    h.endsWith(`.${brand}.com`) ||
    h === `${brand}.net` ||
    h === `${brand}.org`
  );
}

/* ==========================================================================
   PRE-NAVIGATION THREAT SCANNER
   ========================================================================== */

chrome.webNavigation.onBeforeNavigate.addListener(

  async details => {

    /*
      Main frame only
    */

    if (
      details.frameId !== 0
    ) {
      return;
    }

    const url =
      details.url;

    /*
      One-time bypass
    */

    const allowedData =

  await chrome.storage.session.get(
    "shadowlinkAllowedUrls"
  );

const allowedUrls =

  allowedData.shadowlinkAllowedUrls || [];

if (
  allowedUrls.includes(url)
) {

  console.log(
    "[ShadowLink] User allowed:",
    url
  );

  return;
}

    /*
      Ignore browser pages
    */

    if (/^(chrome|chrome-extension|edge|about|data|moz-extension):\/\//.test(url)) {
      return;
    }

    /*
      Parse hostname
    */

    let hostname = "";

    try {

      hostname =

        new URL(url)

          .hostname

          .toLowerCase()

          .replace(/^www\./, "");

    } catch {

      return;
    }

    /*
      Threat lists
    */

    const kwList = typeof suspiciousKeywords !== 'undefined' ? suspiciousKeywords : [];
    const tldList = typeof suspiciousTLDs !== 'undefined' ? suspiciousTLDs : [];
    const brandList = typeof trustedDomains !== 'undefined' ? trustedDomains : [];

    let score = 0;

    const indicators = [];

    /*
      HTTP detection
    */

    if (
      url.startsWith("http://")
    ) {

      score += 15;

      indicators.push(
        "Unencrypted connection (HTTP)"
      );
    }

    /*
      Suspicious TLD
    */

    for (const tld of tldList) {

      if (
        hostname.endsWith(tld)
      ) {

        score += 20;

        indicators.push(
          `Suspicious TLD: ${tld}`
        );

        break;
      }
    }

    /*
      Suspicious keywords
    */

    for (const kw of kwList) {

      if (
        hostname.includes(kw)
      ) {

        score += 10;

        indicators.push(
          `Suspicious keyword in domain: "${kw}"`
        );
      }
    }

    /*
      Raw IP detection
    */

    if (

      /^\d{1,3}(\.\d{1,3}){3}$/

        .test(hostname)

    ) {

      score += 30;

      indicators.push(
        "Raw IP address URL"
      );
    }

    /*
      Brand impersonation
    */

    const label =
      bgExtractLabel(hostname);

    const normLabel =
      normalizeDomain(label);

    const normHostname =
      normalizeDomain(hostname);

    for (const brand of brandList) {

      const normBrand =
        normalizeDomain(brand);

      /*
        Legit domain
      */

      if (
        bgIsBrandHost(
          hostname,
          brand
        )
      ) {
        continue;
      }

      /*
        Exact impersonation
      */

      if (
        normLabel === normBrand
      ) {

        score += 50;

        indicators.push(
          `Brand impersonation: ${brand}`
        );

        break;
      }

      /*
        Embedded brand phishing
      */

      if (

        normHostname.includes(
          normBrand
        )

      ) {

        const hasKeyword =

          kwList.some(
            kw =>
              hostname.includes(kw)
          );

        if (hasKeyword) {

          score += 60;

          indicators.push(
            `Brand ${brand} detected with phishing keywords`
          );

          break;
        }
      }

      /*
        Homoglyph detection
      */

      const dist =

        levenshtein(
          normLabel,
          normBrand
        );

      const maxDist =

        Math.min(

          Math.floor(
            normBrand.length * 0.25
          ),

          2
        );

      if (

        dist >= 1

        &&

        dist <= maxDist

      ) {

        score += 60;

        indicators.push(
          `Homoglyph of ${brand} detected`
        );

        break;
      }
    }

    /*
      Redirect dangerous URLs
    */

    if (
      score >= 60
    ) {


      const reason =

        encodeURIComponent(
          indicators.join(" | ")
        );

      const blockedUrl =

        encodeURIComponent(url);
/*
  Save blocked threat
*/

chrome.storage.local.get(

  ["shadowlinkHistory"],

  data => {

   const history =
  data.shadowlinkHistory || [];

    history.unshift({

  url,

  score,

  indicators,

  threatLevel:
  score >= 75
  ? "Dangerous"

  : score >= 50
  ? "Critical"

  : score >= 25
  ? "Suspicious"

  : "Safe",

  timestamp:
    new Date()
      .toLocaleString()
});

    chrome.storage.local.set({

  shadowlinkHistory:
    history.slice(0, 100)
});
  }
);

/*
  Save timeline event
*/

chrome.storage.local.get(

  ["shadowlinkTimeline"],

  data => {

    const timeline =
      data.shadowlinkTimeline || [];

    const threatLevel =

  score >= 75
    ? "Dangerous"

    : score >= 50
    ? "Critical"

    : score >= 25
    ? "Suspicious"

    : "Safe";

timeline.unshift({

  title:
    threatLevel,

  category:
    threatLevel,

  threatLevel,

  url,

  hostname:
    (() => {

      try {

        return new URL(url)
          .hostname;

      } catch {

        return url;
      }

    })(),

  score,

  indicators,

  timestamp:
    new Date()
      .toLocaleString()
});

    chrome.storage.local.set({

      shadowlinkTimeline:
        timeline.slice(0, 100)
    });
  }
);

      chrome.tabs.update(

        details.tabId,

        {

          url:

            chrome.runtime.getURL(

              `warning/warning.html?url=${blockedUrl}&reason=${reason}`
            )
        }
      );

      return;
    }

    
  }
);


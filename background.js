// =============================================================================
// ShadowLink — background.js
// Service Worker: message handler + pre-navigation threat scanner
// =============================================================================

/* ==========================================================================
   MESSAGE HANDLER
   ========================================================================== */

chrome.runtime.onMessage.addListener(

  (message, sender) => {

    /*
      Screenshot Capture
    */

    if (
      message.type ===
      "CAPTURE_THREAT"
    ) {

      setTimeout(() => {

  chrome.tabs.captureVisibleTab(

    null,

    { format: "png" },

    screenshotUrl => {

      if (
        chrome.runtime.lastError
      ) {
        return;
      }

      chrome.storage.local.get(

        ["shadowlinkScreenshots"],

        data => {

          const screenshots =
            data.shadowlinkScreenshots || [];

          screenshots.unshift({

  url:
    message.url ||

    sender?.tab?.url ||

    "Unknown URL",

  timestamp:
    new Date()
      .toLocaleString(),

  screenshot:
    screenshotUrl
});

          chrome.storage.local.set({

            shadowlinkScreenshots:
              screenshots.slice(0, 20)
          });
        }
      );
    }
  );

}, 300);
}
    /*
      Dynamic Icon Update
    */

    if (
  message.type ===
  "SET_EXTENSION_ICON"
) {

  /*
  |--------------------------------------------------------------------------
  | Use tab-specific update when available
  |--------------------------------------------------------------------------
  */

  if (
    sender?.tab?.id
  ) {

    chrome.action.setIcon({

      path: message.iconPath,

      tabId: sender.tab.id
    });
  }

  /*
  |--------------------------------------------------------------------------
  | Fallback for warning pages
  |--------------------------------------------------------------------------
  */

  else {

    chrome.action.setIcon({

      path: message.iconPath
    });
  }
}
  }
);

/* ==========================================================================
   INLINE LEVENSHTEIN
   ========================================================================== */

function bgLevenshtein(a, b) {

  const m = a.length;

  const n = b.length;

  const dp = Array.from(

    { length: m + 1 },

    (_, i) => {

      const row =
        new Array(n + 1);

      row[0] = i;

      return row;
    }
  );

  for (
    let j = 0;
    j <= n;
    j++
  ) {

    dp[0][j] = j;
  }

  for (
    let i = 1;
    i <= m;
    i++
  ) {

    for (
      let j = 1;
      j <= n;
      j++
    ) {

      dp[i][j] =

        a[i - 1] ===
        b[j - 1]

          ?

          dp[i - 1][j - 1]

          :

          1 + Math.min(

            dp[i - 1][j - 1],

            dp[i][j - 1],

            dp[i - 1][j]
          );
    }
  }

  return dp[m][n];
}

/* ==========================================================================
   NORMALIZATION
   ========================================================================== */

function bgNormalize(s) {

  return s

    .toLowerCase()

    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/3/g, "e")
    .replace(/4/g, "a")
    .replace(/5/g, "s")
    .replace(/7/g, "t")

    .replace(/\u0430/g, "a")
    .replace(/\u0435/g, "e")
    .replace(/\u043E/g, "o")

    .replace(/rn/g, "m")

    .replace(/(.)\1{2,}/g, "$1$1");
}

/* ==========================================================================
   HELPERS
   ========================================================================== */

function bgExtractLabel(hostname) {

  return hostname

    .replace(/^www\./, "")

    .toLowerCase()

    .split(".")[0];
}

function bgIsBrandHost(
  hostname,
  brand
) {

  const h =
    hostname.toLowerCase();

  return (

    h === `${brand}.com`

    ||

    h === `www.${brand}.com`

    ||

    h.endsWith(
      `.${brand}.com`
    )

    ||

    h === `${brand}.net`

    ||

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

    const skipPrefixes = [

      "chrome://",
      "chrome-extension://",
      "edge://",
      "about:",
      "data:",
      "moz-extension://"
    ];

    if (

      skipPrefixes.some(
        p => url.startsWith(p)
      )

    ) {
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

    const suspiciousKeywords = [

      "login",
      "verify",
      "secure",
      "security",
      "account",
      "update",
      "banking",
      "auth",
      "signin",
      "wallet",
      "password",
      "confirm",
      "validate"
    ];

    const suspiciousTlds = [

      ".xyz",
      ".top",
      ".click",
      ".tk",
      ".gq",
      ".ml",
      ".cf",
      ".ga",
      ".work",
      ".support",
      ".zip",
      ".stream",
      ".buzz",
      ".loan",
      ".trade"
    ];

    const targetedBrands = [

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
      "adobe",
      "dropbox"
    ];

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

    for (const tld of suspiciousTlds) {

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

    for (const kw of suspiciousKeywords) {

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
      bgNormalize(label);

    const normHostname =
      bgNormalize(hostname);

    for (const brand of targetedBrands) {

      const normBrand =
        bgNormalize(brand);

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

          suspiciousKeywords.some(
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

        bgLevenshtein(
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

/*
  Capture screenshot evidence
*/

setTimeout(() => {

  chrome.tabs.captureVisibleTab(

    null,

    { format: "png" },

    screenshotUrl => {

      if (
        chrome.runtime.lastError
      ) {
        return;
      }

      chrome.storage.local.get(

        ["shadowlinkScreenshots"],

        data => {

          const screenshots =
            data.shadowlinkScreenshots || [];

          screenshots.unshift({

            url,

            timestamp:
              new Date()
                .toLocaleString(),

            screenshot:
              screenshotUrl
          });

          chrome.storage.local.set({

            shadowlinkScreenshots:
              screenshots.slice(0, 20)
          });
        }
      );
    }
  );

}, 300);
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


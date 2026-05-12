// =============================================================================
// ShadowLink — background.js
// Service Worker: message handler + pre-navigation threat scanner
// =============================================================================

// Single unified message handler
chrome.runtime.onMessage.addListener((message, sender) => {
  // --- Screenshot capture ---
  if (message.type === "CAPTURE_THREAT") {
    chrome.tabs.captureVisibleTab(null, { format: "png" }, (screenshotUrl) => {
      if (chrome.runtime.lastError) return;
      chrome.storage.local.get(["shadowlinkScreenshots"], (data) => {
        const screenshots = data.shadowlinkScreenshots || [];
        screenshots.unshift({
          url: message.url,
          timestamp: new Date().toLocaleString(),
          screenshot: screenshotUrl,
        });
        chrome.storage.local.set({
          shadowlinkScreenshots: screenshots.slice(0, 10),
        });
      });
    });
  }

  // --- Dynamic icon update ---
  if (message.type === "UPDATE_ICON") {
    const iconMap = {
      Safe: "assets/icons/green.png",
      Scanning: "assets/icons/orange.png",
      Warning: "assets/icons/yellow.png",
      Caution: "assets/icons/yellow.png",
      Suspicious: "assets/icons/orange.png",
      Dangerous: "assets/icons/red.png",
    };
    const iconPath = iconMap[message.level] || "assets/icons/green.png";
    if (sender?.tab?.id) {
      chrome.action.setIcon({ path: { 128: iconPath }, tabId: sender.tab.id });
    }
  }
});

// =============================================================================
// INLINE LEVENSHTEIN — for use in background service worker
// (Cannot access content script globals)
// =============================================================================
function bgLevenshtein(a, b) {
  const m = a.length,
    n = b.length;
  const dp = Array.from({ length: m + 1 }, (_, i) => {
    const row = new Array(n + 1);
    row[0] = i;
    return row;
  });
  for (let j = 0; j <= n; j++) dp[0][j] = j;
  for (let i = 1; i <= m; i++) {
    for (let j = 1; j <= n; j++) {
      dp[i][j] =
        a[i - 1] === b[j - 1]
          ? dp[i - 1][j - 1]
          : 1 + Math.min(dp[i - 1][j - 1], dp[i][j - 1], dp[i - 1][j]);
    }
  }
  return dp[m][n];
}

// Minimal normalization for background scanner
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
    .replace(/\u043E/g, "o") // Cyrillic а е о
    .replace(/(.)\1{2,}/g, "$1$1"); // collapse runs of 3+
}

function bgExtractLabel(hostname) {
  return hostname
    .replace(/^www\./, "")
    .toLowerCase()
    .split(".")[0];
}

function bgIsBrandHost(hostname, brand) {
  const h = hostname.toLowerCase();
  return (
    h === `${brand}.com` ||
    h === `www.${brand}.com` ||
    h === `${brand}.net` ||
    h === `${brand}.org` ||
    h.endsWith(`.${brand}.com`) ||
    h.endsWith(`.${brand}.net`)
  );
}

// =============================================================================
// PRE-NAVIGATION THREAT SCANNER
// Fires before the page loads. If score >= 90, redirect to warning page.
//
// NOTE: Threat lists (suspiciousKeywords, suspiciousTlds, targetedBrands)
// are intentionally duplicated here instead of importing from constants.js
// because background.js runs in service worker context and cannot import
// from content scripts. Values are kept in sync with scoring.js spec.
// =============================================================================
chrome.webNavigation.onBeforeNavigate.addListener((details) => {
  if (details.frameId !== 0) return;

  const url = details.url;

  // Skip browser/extension internal pages
  const skipPrefixes = [
    "chrome://",
    "chrome-extension://",
    "edge://",
    "about:",
    "data:",
    "moz-extension://",
  ];
  if (skipPrefixes.some((p) => url.startsWith(p))) return;

  let hostname = "";
  try {
    hostname = new URL(url).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return;
  }

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
    "validate",
  ];
  // ↑ KEEP IN SYNC WITH constants.js::suspiciousKeywords

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
    ".trade",
  ];
  // ↑ KEEP IN SYNC WITH constants.js::suspiciousTLDs

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
    "dropbox",
  ];
  // ↑ KEEP IN SYNC WITH constants.js::trustedDomains

  let score = 0;
  const indicators = [];

  // Rule 1: HTTP (unencrypted)
  if (url.startsWith("http://")) {
    score += 15;
    indicators.push("Unencrypted connection (HTTP)");
  }

  // Rule 2: Suspicious TLD
  // NOTE: Must align with content.js scoring (20 pts per scoring.js spec)
  for (const tld of suspiciousTlds) {
    if (hostname.endsWith(tld)) {
      score += 20;
      indicators.push(`Suspicious TLD: ${tld}`);
      break;
    }
  }

  // Rule 3: Suspicious keywords in hostname only
  // NOTE: Must align with content.js scoring (10 pts per scoring.js spec)
  for (const kw of suspiciousKeywords) {
    if (hostname.includes(kw)) {
      score += 10;
      indicators.push(`Suspicious keyword in domain: "${kw}"`);
    }
  }

  // Rule 4: Raw IP address
  if (/^\d{1,3}(\.\d{1,3}){3}$/.test(hostname)) {
    score += 30;
    indicators.push("Raw IP address URL");
  }

  // Rule 5: Brand impersonation via homoglyph (Levenshtein)
  // NOTE: Must align with scoring.js (60 pts for homoglyph/typosquat)
  // Improved detection: finds brand names anywhere in hostname, not just first label
  const label = bgExtractLabel(hostname);
  const normLabel = bgNormalize(label);
  const normHostname = bgNormalize(hostname); // Check full hostname too

  for (const brand of targetedBrands) {
    const normBrand = bgNormalize(brand);

    // Skip if this IS the legitimate brand host (e.g. microsoft.com)
    if (bgIsBrandHost(hostname, brand)) continue;

    // Strategy 1: Exact first-label match (e.g., "microsoft.xyz")
    if (normLabel === normBrand) {
      score += 50;
      indicators.push(`Brand impersonation: ${brand} on non-official domain`);
      break;
    }

    // Strategy 2: Brand name CONTAINED anywhere in hostname
    // (e.g., "paypal-login-security" contains "paypal", "microsoft-auth-check" contains "microsoft")
    if (normHostname.includes(normBrand)) {
      // Additional confidence check: also has suspicious keywords nearby
      const hasKeyword = suspiciousKeywords.some((kw) =>
        hostname.toLowerCase().includes(kw),
      );
      if (hasKeyword) {
        score += 60;
        indicators.push(
          `Brand ${brand} detected in domain with suspicious keywords`,
        );
        break;
      }
    }

    // Strategy 3: Near-match via Levenshtein (Typo/homoglyph)
    const dist = bgLevenshtein(normLabel, normBrand);
    const maxDist = Math.min(Math.floor(normBrand.length * 0.25), 2);

    if (dist >= 1 && dist <= maxDist) {
      score += 60;
      indicators.push(
        `Homoglyph/typosquat of ${brand} detected (domain: ${label})`,
      );
      break;
    }
  }

  // --- Redirect dangerous/suspicious URLs to warning page ---
  // Threshold: 60 pts = "Suspicious" level (matches scoring.js::classifyThreat)
  if (score >= 60) {
    const reason = encodeURIComponent(indicators.join(" | "));
    const blockedUrl = encodeURIComponent(url);
    chrome.tabs.update(details.tabId, {
      url: chrome.runtime.getURL(
        `warning/warning.html?url=${blockedUrl}&reason=${reason}`,
      ),
    });
    return;
  }

  // --- Update icon with a preliminary colour for lower-risk scores ---
  let iconPath = "assets/icons/green.png";
  if (score >= 60) iconPath = "assets/icons/orange.png";
  else if (score >= 25) iconPath = "assets/icons/yellow.png";

  chrome.action.setIcon({ path: { 128: iconPath }, tabId: details.tabId });
});

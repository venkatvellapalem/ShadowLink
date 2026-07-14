/* global suspiciousTLDs, suspiciousKeywords, detectHomoglyph, trustedDomains */

function analyzeURL(url) {
  const indicators = [];

  let hostname = "";
  try {
    hostname = new URL(url).hostname.toLowerCase().replace(/^www\./, "");
  } catch {
    return { indicators };
  }

  if (Array.isArray(suspiciousTLDs)) {
    suspiciousTLDs.forEach(tld => {
      if (hostname.endsWith(tld)) {
        indicators.push("Suspicious TLD detected: " + tld);
      }
    });
  }

  if (url.startsWith("http://")) {
    indicators.push("Website is not using HTTPS");
  }

  if (Array.isArray(suspiciousKeywords)) {
    suspiciousKeywords.forEach(keyword => {
      if (hostname.includes(keyword)) {
        indicators.push("Suspicious keyword found: " + keyword);
      }
    });
  }

  const hostnameParts = hostname.split(".");
  const rootDomain = hostnameParts.length > 2
    ? hostnameParts[hostnameParts.length - 2]
    : hostnameParts[0];

  if (typeof detectHomoglyph === "function" && Array.isArray(trustedDomains)) {
    const homoglyphMatches = detectHomoglyph(rootDomain, trustedDomains);
    if (homoglyphMatches.length > 0) {
      indicators.push("Possible homoglyph attack targeting: " + homoglyphMatches.join(", "));
    }
  }

  return { indicators };
}
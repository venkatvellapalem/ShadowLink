function analyzeURL(url) {

  let score = 0;
  let indicators = [];

  suspiciousTLDs.forEach(tld => {

    if (url.includes(tld)) {

      score += 20;

      indicators.push(
        `Suspicious TLD detected: ${tld}`
      );
    }
  });

  if (url.startsWith("http://")) {

    score += 15;

    indicators.push(
      "Website is not using HTTPS"
    );
  }

  suspiciousKeywords.forEach(keyword => {

    if (
      url.toLowerCase().includes(keyword)
    ) {

      score += 10;

      indicators.push(
        `Suspicious keyword found: ${keyword}`
      );
    }
  });

  const currentDomain =
    window.location.hostname
      .replace("www.", "")
      .split(".")[0];

  const homoglyphMatches =
    detectHomoglyph(
      currentDomain,
      trustedDomains
    );

  if (homoglyphMatches.length > 0) {

    score += 60;

    indicators.push(
      `Possible homoglyph attack targeting: ${homoglyphMatches.join(", ")}`
    );
  }

  return {
    score,
    indicators
  };
}
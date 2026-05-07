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

    if (url.toLowerCase().includes(keyword)) {

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
console.log("Current Domain:", currentDomain);
const homoglyphMatches =
  detectHomoglyph(
    currentDomain,
    trustedDomains
  );

console.log(
  "Homoglyph Matches:",
  homoglyphMatches
);
console.log({
  domain,
  trusted,
  distance
});

if (homoglyphMatches.length > 0) {

  score += 40;

  indicators.push(
    `Possible homoglyph attack targeting: ${homoglyphMatches.join(", ")}`
  );
}
  return {
    score,
    indicators
  };
}
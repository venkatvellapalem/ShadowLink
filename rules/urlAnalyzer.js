function analyzeURL(url) {


  let indicators = [];

  let hostname = "";

  try {

    hostname =
      new URL(url)
        .hostname
        .toLowerCase()
        .replace("www.", "");

  } catch {

    return {
      indicators: []
    };
  }

  /*
    Suspicious TLD
  */

  suspiciousTLDs.forEach(tld => {

    if (
      hostname.endsWith(tld)
    ) {


      indicators.push(
        `Suspicious TLD detected: ${tld}`
      );
    }
  });

  /*
    HTTP detection
  */

  if (
    url.startsWith("http://")
  ) {


    indicators.push(
      "Website is not using HTTPS"
    );
  }

  /*
    Suspicious keywords
    ONLY in hostname
  */

  suspiciousKeywords.forEach(keyword => {

    if (
      hostname.includes(keyword)
    ) {


      indicators.push(
        `Suspicious keyword found: ${keyword}`
      );
    }
  });

  /*
    Root domain extraction
  */

  const hostnameParts =
  hostname.split(".");

const rootDomain =
  hostnameParts.length > 2

    ? hostnameParts[
        hostnameParts.length - 2
      ]

    : hostnameParts[0];

  /*
    Homoglyph detection
  */

  const homoglyphMatches =
    detectHomoglyph(
      rootDomain,
      trustedDomains
    );

  if (
    homoglyphMatches.length > 0
  ) {


    indicators.push(
      `Possible homoglyph attack targeting: ${homoglyphMatches.join(", ")}`
    );
  }

  return {
    indicators
  };
}
function levenshtein(a, b) {

  const matrix = [];

  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }

  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= b.length; i++) {

    for (let j = 1; j <= a.length; j++) {

      if (
        b.charAt(i - 1) ===
        a.charAt(j - 1)
      ) {

        matrix[i][j] =
          matrix[i - 1][j - 1];

      } else {

        matrix[i][j] = Math.min(
          matrix[i - 1][j - 1] + 1,
          matrix[i][j - 1] + 1,
          matrix[i - 1][j] + 1
        );
      }
    }
  }

  return matrix[b.length][a.length];
}

/*
  Normalize homoglyph tricks
*/

function normalizeDomain(domain) {

  return domain

    .toLowerCase()

    /*
      Common number replacements
    */

    .replace(/0/g, "o")
    .replace(/1/g, "l")
    .replace(/3/g, "e")
    .replace(/5/g, "s")
    .replace(/7/g, "t")

    /*
      Symbol replacements
    */

    .replace(/@/g, "a")
    .replace(/\$/g, "s")

    /*
      Visual homoglyph combos
    */

    .replace(/rn/g, "m")
    .replace(/vv/g, "w")
    .replace(/cl/g, "d")
    .replace(/ii/g, "n")

    /*
      Remove separators
    */

    .replace(/-/g, "")
    .replace(/_/g, "")
    .replace(/\./g, "");
}

/*
  Detect homoglyph attacks
*/

function detectHomoglyph(
  domain,
  trustedDomains
) {

  const suspiciousMatches = [];

  const normalizedDomain =
    normalizeDomain(domain);

  trustedDomains.forEach(trusted => {

    const normalizedTrusted =
      normalizeDomain(trusted);

    /*
      Exact match
      means safe
    */

    if (
      normalizedDomain ===
      normalizedTrusted
    ) {
      return;
    }

    /*
      Ignore if trusted word
      simply appears inside
      larger legit domain
    */

    const phishingSeparators = [

  "secure",
  "login",
  "auth",
  "verify",
  "account",
  "update"
];

const containsTrusted =
  normalizedDomain.includes(
    normalizedTrusted
  );

const hasPhishingPattern =
  phishingSeparators.some(
    part =>
      normalizedDomain.includes(part)
  );

/*
  Legit larger domains
  like googleapis
  should NOT trigger
*/

const legitExtensions = [

  "googleapis",
  "googleusercontent",
  "gstatic",
  "githubusercontent"
];

const looksLegit =
  legitExtensions.some(
    legit =>
      normalizedDomain.includes(legit)
  );

if (looksLegit) {
  return;
}

    const distance =
      levenshtein(

        normalizedDomain,

        normalizedTrusted
      );

    /*
      STRICT thresholds
    */

    if (

      (
        normalizedTrusted.length <= 6
        && distance <= 1
      )

      ||

      (
        normalizedTrusted.length > 6
        && distance <= 2
      )

    ) {

      suspiciousMatches.push(
        trusted
      );
    }
  });

  return suspiciousMatches;
}
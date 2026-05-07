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

      if (b.charAt(i - 1) === a.charAt(j - 1)) {

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

function detectHomoglyph(domain, trustedDomains) {

  let suspiciousMatches = [];

  trustedDomains.forEach(trusted => {

    const distance =
      levenshtein(domain, trusted);

    console.log(
    "Testing:",
      domain,
      trusted,
      "distance:",
      distance
    );

    console.log({
  domain,
  trusted,
  distance
});

    if (
      distance > 0 &&
      distance <= 2
    ) {

      suspiciousMatches.push(trusted);
    }
  });

  return suspiciousMatches;
}
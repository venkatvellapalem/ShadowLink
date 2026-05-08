const suspiciousTlds = [

  ".xyz",
  ".top",
  ".click",
  ".gq",
  ".tk",
  ".ml",
  ".cf",
  ".ga",
  ".work",
  ".support",
  ".zip",
  ".country",
  ".stream",
  ".xin",
  ".buzz"
];

function checkSuspiciousTLD(url) {

  try {

    const hostname =
      new URL(url)
        .hostname
        .toLowerCase();

    const indicators = [];

    suspiciousTlds.forEach(tld => {

      if (
        hostname.endsWith(tld)
      ) {

        indicators.push(
          `Suspicious TLD detected (${tld})`
        );
      }
    });

    return indicators;

  } catch {

    return [];
  }
}
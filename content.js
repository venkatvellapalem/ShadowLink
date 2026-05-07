/* global checkVirusTotal */
let vtStats = null;
const engine =
  createThreatEngine();

const result =
  analyzeURL(
    window.location.href
  );

  (async () => {

  const result =
    analyzeURL(window.location.href);

  const loginIndicators =
    detectLoginForms();

  result.indicators.push(
    ...loginIndicators
  );

  result.score +=
    loginIndicators.length * 20;

  const vtStats =
    await checkVirusTotal(
      window.location.href
    );

  console.log(
    "VirusTotal Stats:",
    vtStats
  );

  if (vtStats) {

    const malicious =
      vtStats.malicious || 0;

    const suspicious =
      vtStats.suspicious || 0;

    if (malicious > 0) {

      result.score += 80;

      result.indicators.push(
        `VirusTotal flagged malicious (${malicious} vendors)`
      );

      result.breakdown.push({
        points: 80,
        reason:
          `VirusTotal malicious detection (${malicious} vendors)`
      });
    }

    if (suspicious > 0) {

      result.score += 40;

      result.indicators.push(
        `VirusTotal flagged suspicious (${suspicious} vendors)`
      );

      result.breakdown.push({
        points: 40,
        reason:
          `VirusTotal suspicious detection (${suspicious} vendors)`
      });
    }
  }

  result.threatLevel =
    classifyThreat(result.score);

  console.log(
    "ShadowLink Analysis:",
    result
  );

  showWarningBanner(result);

  showDangerOverlay(result);

  window.shadowLinkData =
    result;

  if (
    result.score >= 50
  ) {

    saveThreat(result);

    chrome.runtime.sendMessage({

      type: "CAPTURE_THREAT",

      url:
        window.location.href
    });
  }

})();

window.shadowLinkData =
  result;

showWarningBanner(result);

showDangerOverlay(result);

checkVirusTotal(
  window.location.href
).then(stats => {

  if (!stats) {
    return;
  }

  if (
    stats.malicious > 0
  ) {

    result.score += 50;

    result.indicators.push(

      `VirusTotal detected ${stats.malicious} malicious engines`
    );
  }

  if (
    stats.suspicious > 0
  ) {

    result.score += 30;

    result.indicators.push(

      `VirusTotal marked URL suspicious`
    );
  }

  result.threatLevel =
    classifyThreat(result.score);

  window.shadowLinkData =
    result;

  showWarningBanner(result);

  showDangerOverlay(result);
});

/*
  Transfer URL analysis
  into engine
*/

result.indicators.forEach(
  indicator => {

    if (
      indicator.includes(
        "homoglyph"
      )
    ) {

      engine.addThreat(
        60,
        indicator
      );

    } else if (
      indicator.includes(
        "HTTPS"
      )
    ) {

      engine.addThreat(
        15,
        indicator
      );

    } else {

      engine.addThreat(
        10,
        indicator
      );
    }
  }
);

/*
  Login form analysis
*/

const loginIndicators =
  detectLoginForms();

loginIndicators.forEach(
  indicator => {

    engine.addThreat(
      20,
      indicator
    );
  }
);

/*
  Final result
*/

const finalResult = {

  score:
    engine.score,

  indicators:
    engine.indicators,

  breakdown:
    engine.breakdown
};

finalResult.threatLevel =
  classifyThreat(
    finalResult.score
  );

console.log(
  "ShadowLink Analysis:",
  finalResult
);

/*
  UI
*/

showWarningBanner(
  finalResult
);

showDangerOverlay(
  finalResult
);

window.shadowLinkData =
  finalResult;

/*
  Save threat history
*/

if (
  finalResult.threatLevel !==
  "Safe"
) {

  saveThreat(finalResult);
}

/*
  Capture evidence
*/

if (
  result.score >= 50
) {

  chrome.runtime.sendMessage({

    type:
      "CAPTURE_THREAT",

    url:
      window.location.href
  });
}
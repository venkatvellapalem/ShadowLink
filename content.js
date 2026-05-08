chrome.runtime.onMessage.addListener(

  message => {

    if (

      message.type ===
      "SHOW_THREAT_POPUP"

    ) {

      showThreatPopup(
        message.data
      );
    }
  }
);
/* global checkVirusTotal */

const engine =
  createThreatEngine();

(async () => {

  /*
    Base URL analysis
  */

  const result =
    analyzeURL(
      window.location.href
    );

  /*
    Login form detection
  */

  const loginIndicators =
    detectLoginForms();

  result.indicators.push(
    ...loginIndicators
  );

  result.score +=
    loginIndicators.length * 20;

  /*
    Suspicious TLD detection
  */

  const tldIndicators =
    checkSuspiciousTLD(
      window.location.href
    );

  result.indicators.push(
    ...tldIndicators
  );

  result.score +=
    tldIndicators.length * 30;

  /*
    Add indicators into engine
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
      }

      else if (
        indicator.includes(
          "Suspicious TLD"
        )
      ) {

        engine.addThreat(
          35,
          indicator
        );
      }

      else {

        engine.addThreat(
          20,
          indicator
        );
      }
    }
  );

  /*
    VirusTotal + Domain Age
  */

  const vtResult =
    await checkVirusTotal(
      window.location.href
    );

  const vtStats =
    vtResult?.stats;

  const domainAgeDays =
    vtResult?.domainAgeDays;

  console.log(
    "VirusTotal Stats:",
    vtStats
  );

  /*
    Domain Age Threats
  */

  if (
    domainAgeDays !== null
  ) {

    if (
      domainAgeDays < 30
    ) {

      engine.addThreat(

        70,

        `Very new domain (${domainAgeDays} days old)`
      );
    }

    else if (
      domainAgeDays < 90
    ) {

      engine.addThreat(

        40,

        `Recently registered domain (${domainAgeDays} days old)`
      );
    }
  }

  /*
    VirusTotal Threats
  */

  if (vtStats) {

    const malicious =
      vtStats.malicious || 0;

    const suspicious =
      vtStats.suspicious || 0;

    if (malicious > 0) {

      if (malicious >= 5) {

  engine.addThreat(
    80,
    `VirusTotal flagged malicious (${malicious} vendors)`
  );
}

else if (malicious > 0) {

  engine.addThreat(
    30,
    `VirusTotal flagged suspicious (${malicious} vendors)`
  );
}
    }

    if (suspicious > 0) {

      engine.addThreat(

        40,

        `VirusTotal flagged suspicious (${suspicious} vendors)`
      );
    }
  }

  /*
    Final Result
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
    Save globally
  */

  window.shadowLinkData =
    finalResult;

  /*
    Floating popup
  */

  if (

    finalResult.threatLevel ===
    "Suspicious"

    ||

    finalResult.threatLevel ===
    "Dangerous"

  ) {

    showThreatPopup(
      finalResult
    );
  }

  /*
    Update extension icon
  */

  chrome.runtime.sendMessage({

    type:
      "UPDATE_ICON",

    level:
      finalResult.threatLevel
  });

  /*
    Save threat history
  */

  if (

    finalResult.threatLevel !==
    "Safe"

  ) {

    saveThreat(
      finalResult
    );
  }

  /*
    Capture evidence
  */

  if (
    finalResult.score >= 50
  ) {

    chrome.runtime.sendMessage({

      type:
        "CAPTURE_THREAT",

      url:
        window.location.href
    });
  }

})();


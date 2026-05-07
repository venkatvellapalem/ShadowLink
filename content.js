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

      } else {

        engine.addThreat(
          20,
          indicator
        );
      }
    }
  );

  /*
    VirusTotal check
  */

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

      engine.addThreat(

        80,

        `VirusTotal flagged malicious (${malicious} vendors)`
      );
    }

    if (suspicious > 0) {

      engine.addThreat(

        40,

        `VirusTotal flagged suspicious (${suspicious} vendors)`
      );
    }
  }

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
    chrome.runtime.sendMessage({

  type: "UPDATE_ICON",

  level:
    finalResult.threatLevel
});

  console.log(
    "ShadowLink Analysis:",
    finalResult
  );

  /*
    Save globally
  */

  window.shadowLinkData =
    finalResult;

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
    Dangerous overlay ONLY
  */

  if (

    finalResult.threatLevel ===
    "Dangerous"

  ) {

    
  }

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
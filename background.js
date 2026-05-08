chrome.runtime.onMessage.addListener(

  (message, sender) => {

    /*
      Screenshot Capture
    */

    if (
      message.type ===
      "CAPTURE_THREAT"
    ) {

      chrome.tabs.captureVisibleTab(

        null,

        { format: "png" },

        screenshotUrl => {

          chrome.storage.local.get(

            ["shadowlinkScreenshots"],

            data => {

              const screenshots =
                data.shadowlinkScreenshots || [];

              screenshots.unshift({

                url:
                  message.url,

                timestamp:
                  new Date()
                    .toLocaleString(),

                screenshot:
                  screenshotUrl
              });

              chrome.storage.local.set({

                shadowlinkScreenshots:
                  screenshots.slice(0, 10)
              });
            }
          );
        }
      );
    }

    /*
      Dynamic Icon Update
    */

    if (
      message.type ===
      "UPDATE_ICON"
    ) {

      let iconPath =
        "assets/icons/green.png";

      if (
        message.level ===
        "Caution"
      ) {

        iconPath =
          "assets/icons/yellow.png";
      }

      if (
        message.level ===
        "Suspicious"
      ) {

        iconPath =
          "assets/icons/orange.png";
      }

      if (
        message.level ===
        "Dangerous"
      ) {

        iconPath =
          "assets/icons/red.png";
      }

      chrome.action.setIcon({

        path: {
          128: iconPath
        },

        tabId:
          sender.tab.id
      });
    }
  }
);

/*
  Pre-navigation threat scan
*/

chrome.webNavigation.onBeforeNavigate.addListener(

  details => {

    /*
      Main frame only
    */

    if (
      details.frameId !== 0
    ) {
      return;
    }

    const url =
      details.url.toLowerCase();

    /*
      Ignore browser pages
    */

    if (

      url.startsWith(
        "chrome://"
      )

      ||

      url.startsWith(
        "chrome-extension://"
      )

      ||

      url.startsWith(
        "edge://"
      )

    ) {
      return;
    }

    /*
      Intelligence lists
    */

    const suspiciousKeywords = [

      "login",
      "verify",
      "secure",
      "account",
      "update",
      "banking",
      "auth",
      "signin",
      "wallet",
      "password"
    ];

    const suspiciousTlds = [

      ".xyz",
      ".top",
      ".click",
      ".tk",
      ".gq",
      ".ml",
      ".cf"
    ];

    const targetedBrands = [

      "google",
      "paypal",
      "microsoft",
      "facebook",
      "apple",
      "amazon",
      "instagram",
      "netflix"
    ];

    let score = 0;

    const indicators = [];

    /*
      Keyword detection
    */

    suspiciousKeywords.forEach(

      keyword => {

        if (
          url.includes(
            keyword
          )
        ) {

          score += 30;

          indicators.push(

            `Suspicious keyword detected: ${keyword}`
          );
        }
      }
    );

    /*
      Suspicious TLD detection
    */

    suspiciousTlds.forEach(

      tld => {

        if (
          url.includes(
            tld
          )
        ) {

          score += 40;

          indicators.push(

            `Suspicious TLD detected: ${tld}`
          );
        }
      }
    );

    /*
      Brand impersonation
    */

    targetedBrands.forEach(

      brand => {

        if (
          url.includes(
            brand
          )
        ) {

          score += 40;

          indicators.push(

            `Possible impersonation of ${brand}`
          );
        }
      }
    );

    /*
      Threat classification
    */

    let threatLevel =
      "Safe";

    if (
      score >= 90
    ) {

      threatLevel =
        "Dangerous";
    }

    else if (
      score >= 40
    ) {

      threatLevel =
        "Suspicious";
    }

    /*
      Dynamic icon
    */

    let iconPath =
      "assets/icons/green.png";

    if (
      threatLevel ===
      "Suspicious"
    ) {

      iconPath =
        "assets/icons/orange.png";
    }

    if (
      threatLevel ===
      "Dangerous"
    ) {

      iconPath =
        "assets/icons/red.png";
    }

    chrome.action.setIcon({

      path: {
        128: iconPath
      },

      tabId:
        details.tabId
    });

    /*
  Dangerous dead-domain redirect
*/

if (

  threatLevel ===
  "Dangerous"

) {

  const reason =

    encodeURIComponent(

      indicators.join(" | ")

    );

  chrome.tabs.update(

    details.tabId,

    {

      url:

      chrome.runtime.getURL(

        `warning/warning.html?reason=${reason}`
      )
    }
  );

  return;
}

/*
  Suspicious popup
*/

if (

  threatLevel ===
  "Suspicious"

) {

  chrome.tabs.sendMessage(

    details.tabId,

    {

      type:
        "SHOW_THREAT_POPUP",

      data: {

        score,
        indicators,
        threatLevel
      }
    }
  );
}
  }
);
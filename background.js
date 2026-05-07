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

        tabId: sender.tab.id
      });
    }
  }
);
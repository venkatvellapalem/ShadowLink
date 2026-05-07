chrome.runtime.onMessage.addListener(

  (message, sender) => {

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
  }
);
chrome.tabs.query(
  {
    active: true,
    currentWindow: true
  },

  tabs => {

    const currentTab = tabs[0];

    document.getElementById("site")
      .innerText = currentTab.url;

    chrome.scripting.executeScript(
      {
        target: {
          tabId: currentTab.id
        },

        func: () => {

          const banner =
            document.getElementById(
              "shadowlink-banner"
            );

          if (!banner) {

            return {
              threatLevel: "Safe",
              score: 0,
              indicators: []
            };
          }

          return window.shadowLinkData || {
            threatLevel: "Safe",
            score: 0,
            indicators: []
          };
        }
      },

      results => {

        if (!results || !results[0]) {
          return;
        }

        const data =
          results[0].result;

        document.getElementById(
          "threatLevel"
        ).innerText =
          data.threatLevel;

        document.getElementById(
          "riskScore"
        ).innerText =
          data.score;

        document.getElementById(
          "indicators"
        ).innerHTML =
          data.indicators.join("<br>");
      }
    );
  }
);

chrome.storage.local.get(
  ["shadowlinkHistory"],

  data => {

    const history =
      data.shadowlinkHistory || [];

    const historyContainer =
      document.getElementById(
        "history"
      );

    if (history.length === 0) {

      historyContainer.innerText =
        "No threats detected.";

      return;
    }

    historyContainer.innerHTML =
      history.map(item => `

        <div style="
          margin-bottom:12px;
          padding-bottom:10px;
          border-bottom:
          1px solid rgba(255,255,255,0.08);
        ">

          <div style="
            color:#FF4D6D;
            font-weight:bold;
          ">
            ${item.threatLevel}
          </div>

          <div style="
            font-size:12px;
            opacity:0.8;
            word-break:break-word;
          ">
            ${item.url}
          </div>

          <div style="
            font-size:11px;
            opacity:0.6;
            margin-top:4px;
          ">
            ${item.timestamp}
          </div>

        </div>

      `).join("");
  }
);
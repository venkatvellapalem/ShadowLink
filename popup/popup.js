chrome.tabs.query(
  {
    active: true,
    currentWindow: true
  },

  tabs => {

    const currentTab = tabs[0];

    document.getElementById(
      "site"
    ).innerText =
      currentTab.url;

    chrome.scripting.executeScript(

      {
        target: {
          tabId: currentTab.id
        },

        func: () => {

          return (
            window.shadowLinkData || {

              threatLevel: "Safe",

              score: 0,

              indicators: [],

              breakdown: []
            }
          );
        }
      },

      results => {

        if (
          !results ||
          !results[0]
        ) {
          return;
        }

        const data =
          results[0].result;

        /*
          Threat Level
        */

        document.getElementById(
          "threatLevel"
        ).innerText =
          data.threatLevel;

        /*
          Risk Score
        */

        document.getElementById(
          "riskScore"
        ).innerText =
          data.score;

        /*
          Indicators
        */

        document.getElementById(
          "indicators"
        ).innerHTML =
          data.indicators.join("<br>");
          if (data.breakdown) {

  document.getElementById(
    "breakdown"
  ).innerHTML =

    data.breakdown
      .map(item => `

        <div style="
          margin-bottom:8px;
        ">

          <span style="
            color:#FF4D6D;
            font-weight:bold;
          ">
            +${item.points}
          </span>

          ${item.reason}

        </div>

      `)
      .join("");
}

        /*
          Breakdown
        */

        if (data.breakdown) {

          document.getElementById(
            "breakdown"
          ).innerHTML =

            data.breakdown
              .map(item => `

                <div style="
                  margin-bottom:8px;
                ">

                  <span style="
                    color:#FF4D6D;
                    font-weight:bold;
                  ">
                    +${item.points}
                  </span>

                  ${item.reason}

                </div>

              `)
              .join("");
        }
      }
    );
  }
);

/*
  Threat History
*/

chrome.storage.local.get(

  ["shadowlinkHistory"],

  data => {

    const history =
      data.shadowlinkHistory || [];

    const historyContainer =
      document.getElementById(
        "history"
      );

    if (
      history.length === 0
    ) {

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

/*
  Screenshots
*/

chrome.storage.local.get(

  ["shadowlinkScreenshots"],

  data => {

    const screenshots =
      data.shadowlinkScreenshots || [];

    const container =
      document.getElementById(
        "screenshots"
      );

    if (
      screenshots.length === 0
    ) {

      container.innerText =
        "No screenshots captured.";

      return;
    }

    container.innerHTML =

      screenshots.map(item => `

        <div style="
          margin-bottom:18px;
        ">

          <img
            src="${item.screenshot}"

            style="
              width:100%;
              border-radius:10px;
              margin-bottom:8px;
              border:
              1px solid rgba(255,255,255,0.08);
            "
          />

          <div style="
            font-size:11px;
            opacity:0.7;
            word-break:break-word;
          ">
            ${item.url}
          </div>

        </div>

      `).join("");
  }
);
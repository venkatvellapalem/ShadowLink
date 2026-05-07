function saveThreat(result) {

  chrome.storage.local.get(
    ["shadowlinkHistory"],

    data => {

      const history =
        data.shadowlinkHistory || [];

      history.unshift({

        url: window.location.href,

        threatLevel:
          result.threatLevel,

        score:
          result.score,

        indicators:
          result.indicators,

        timestamp:
          new Date().toLocaleString()
      });

      // Keep only latest 20
      const trimmedHistory =
        history.slice(0, 20);

      chrome.storage.local.set({

        shadowlinkHistory:
          trimmedHistory
      });
    }
  );
}
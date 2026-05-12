/* ==========================================================================
   ShadowLink — warning.js
   ========================================================================== */

(function () {

  "use strict";

  const params =
    new URLSearchParams(
      window.location.search
    );

  const reason =
    params.get("reason") || "";

  const url =
    params.get("url") || "";

  /*
    Display blocked URL
  */

  const blockedUrlEl =
    document.getElementById(
      "blockedUrl"
    );

  if (blockedUrlEl) {

    blockedUrlEl.textContent =
      url;
  }

  /*
    Render indicators
  */

  const listEl =
    document.getElementById(
      "indicatorList"
    );

  if (listEl && reason) {

    const indicators = reason

      .split(" | ")

      .map(i => i.trim())

      .filter(Boolean);

    listEl.innerHTML =

      indicators

        .map(indicator =>

          `<li>${escapeHTML(indicator)}</li>`

        )

        .join("");
  }

  /*
    Back button
  */

  const backBtn =
    document.getElementById(
      "backBtn"
    );

  if (backBtn) {

    backBtn.onclick = () => {

      history.back();
    };
  }

  /*
    Proceed button
  */

  const proceedBtn =
    document.getElementById(
      "proceedBtn"
    );

  if (proceedBtn) {

    proceedBtn.onclick = async () => {

      /*
        Save bypass URL
      */

      const data =

  await chrome.storage.session.get(
    "shadowlinkAllowedUrls"
  );

const allowed =
  data.shadowlinkAllowedUrls || [];

if (
  !allowed.includes(url)
) {

  allowed.push(url);
}

await chrome.storage.session.set({

  shadowlinkAllowedUrls:
    allowed
});

      /*
        Redirect to original URL
      */

      window.location.href =
        url;
    };
  }

  /*
    Escape HTML
  */

  function escapeHTML(str) {

    return str

      .replace(/&/g, "&amp;")

      .replace(/</g, "&lt;")

      .replace(/>/g, "&gt;")

      .replace(/"/g, "&quot;")

      .replace(/'/g, "&#039;");
  }

})();
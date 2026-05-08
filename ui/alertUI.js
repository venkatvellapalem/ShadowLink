function showThreatPopup(result) {

  if (
    document.getElementById(
      "shadowlink-popup"
    )
  ) {
    return;
  }

  const popup =
    document.createElement("div");

  popup.id =
    "shadowlink-popup";

  let borderColor =
    "#00FFB3";

  let glow =
    "rgba(0,255,179,0.35)";

  if (
    result.threatLevel ===
    "Caution"
  ) {

    borderColor =
      "#FFD93D";

    glow =
      "rgba(255,217,61,0.35)";
  }

  if (
    result.threatLevel ===
    "Suspicious"
  ) {

    borderColor =
      "#FF9F43";

    glow =
      "rgba(255,159,67,0.35)";
  }

  if (
    result.threatLevel ===
    "Dangerous"
  ) {

    borderColor =
      "#FF4D6D";

    glow =
      "rgba(255,77,109,0.4)";
  }

  popup.style.cssText = `

    position:fixed;
    top:24px;
    right:24px;
    width:360px;
    background:#070B1AEE;
    backdrop-filter:blur(14px);
    border:2px solid ${borderColor};
    border-radius:22px;
    padding:22px;
    z-index:999999999;
    color:white;
    font-family:Arial,sans-serif;
    box-shadow:0 0 30px ${glow};
    animation:shadowlinkSlide 0.35s ease;
  `;

  popup.innerHTML = `

    <div style="
      display:flex;
      justify-content:space-between;
      align-items:center;
      margin-bottom:16px;
    ">

      <div style="
        font-size:34px;
      ">
        🛡️
      </div>

      <button id="shadowlink-close"
      style="
        background:none;
        border:none;
        color:white;
        font-size:20px;
        cursor:pointer;
      ">
        ✕
      </button>

    </div>

    <div style="
      font-size:30px;
      font-weight:bold;
      margin-bottom:10px;
      color:${borderColor};
    ">
      ${result.threatLevel}
    </div>

    <div style="
      font-size:16px;
      opacity:0.92;
      line-height:1.5;
      margin-bottom:18px;
    ">
      ${result.indicators.join("<br>")}
    </div>

    <div style="
      display:flex;
      justify-content:space-between;
      align-items:center;
    ">

      <div style="
        font-size:14px;
        opacity:0.7;
      ">
        Risk Score:
        ${result.score}
      </div>

      <button id="shadowlink-dismiss"
      style="
        background:${borderColor};
        border:none;
        color:black;
        padding:10px 16px;
        border-radius:12px;
        font-weight:bold;
        cursor:pointer;
      ">
        Dismiss
      </button>

    </div>
  `;

  const style =
    document.createElement("style");

  style.innerHTML = `

    @keyframes shadowlinkSlide {

      from {
        transform:
          translateX(60px);
        opacity:0;
      }

      to {
        transform:
          translateX(0);
        opacity:1;
      }
    }
  `;

  document.head.appendChild(style);

  document.body.appendChild(
    popup
  );
  if (

  result.threatLevel ===
  "Dangerous"

) {

  popup.animate(

    [

      {
        transform:
          "translateX(-4px)"
      },

      {
        transform:
          "translateX(4px)"
      },

      {
        transform:
          "translateX(-4px)"
      },

      {
        transform:
          "translateX(0px)"
      }

    ],

    {

      duration: 300,

      iterations: 2
    }
  );
}

  document.getElementById(
    "shadowlink-close"
  ).onclick = () => {

    popup.remove();
  };

  document.getElementById(
    "shadowlink-dismiss"
  ).onclick = () => {

    popup.remove();
  };

  /*
  Auto-hide popup
*/

if (

  result.threatLevel ===
  "Suspicious"

  ||

  result.threatLevel ===
  "Dangerous"

) {

  setTimeout(() => {

    if (popup) {

      popup.remove();
    }

  }, 8000);
}
}
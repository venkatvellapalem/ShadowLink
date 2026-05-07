function showWarningBanner(result) {

  const existingBanner =
    document.getElementById("shadowlink-banner");

  if (existingBanner) {
    existingBanner.remove();
  }

  const banner = document.createElement("div");

  banner.id = "shadowlink-banner";

  let borderColor = "#00FFB2";

  if (result.threatLevel === "Suspicious") {
    borderColor = "#FFD93D";
  }

  if (result.threatLevel === "Dangerous") {
    borderColor = "#FF4D6D";
  }

  banner.innerHTML = `
  
    <div style="
      font-size:18px;
      font-weight:bold;
      margin-bottom:10px;
    ">
      ShadowLink
    </div>

    <div style="margin-bottom:8px;">

      Threat Level:

      <span style="
        color:${borderColor};
        font-weight:bold;
      ">
        ${result.threatLevel}
      </span>

    </div>

    <div style="margin-bottom:8px;">
      Risk Score: ${result.score}
    </div>

    <div style="
      font-size:13px;
      opacity:0.9;
    ">

      ${result.indicators.join("<br>")}

    </div>
  `;

  banner.style.position = "fixed";
  banner.style.top = "20px";
  banner.style.right = "20px";

  banner.style.width = "320px";

  banner.style.zIndex = "999999";

  banner.style.background =
    "rgba(5,8,22,0.95)";

  banner.style.backdropFilter =
    "blur(10px)";

  banner.style.color = "#E6F1FF";

  banner.style.padding = "18px";

  banner.style.border =
    `2px solid ${borderColor}`;

  banner.style.borderRadius = "14px";

  banner.style.boxShadow =
    `0 0 25px ${borderColor}55`;

  banner.style.fontFamily =
    "Arial, sans-serif";

  banner.style.fontSize = "14px";

  banner.style.lineHeight = "1.5";

  document.body.appendChild(banner);
}
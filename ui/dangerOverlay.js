function showDangerOverlay(result) {

  if (
  result.score < 100
) {
    return;
  }

  const overlay =
    document.createElement("div");

  overlay.id =
    "shadowlink-danger-overlay";

  overlay.innerHTML = `
  
    <div style="
      text-align:center;
      max-width:600px;
    ">

      <h1 style="
        color:#FF4D6D;
        font-size:42px;
        margin-bottom:20px;
      ">
        ⚠ PHISHING WARNING
      </h1>

      <p style="
        font-size:20px;
        margin-bottom:20px;
      ">
        ShadowLink detected a potentially dangerous phishing website.
      </p>

      <p style="
        font-size:16px;
        opacity:0.9;
        margin-bottom:30px;
      ">
        Do NOT enter passwords, OTPs, or banking credentials.
      </p>

      <button id="shadowlink-proceed-btn"
      style="
        padding:14px 24px;
        border:none;
        border-radius:10px;
        background:#FF4D6D;
        color:white;
        font-size:16px;
        cursor:pointer;
      ">
        Proceed Anyway
      </button>

    </div>
  `;

  overlay.style.position = "fixed";
  overlay.style.top = "0";

  overlay.style.width = "100vw";
  overlay.style.height = "100vh";

  overlay.style.background =
    "rgba(5,8,22,0.92)";

  overlay.style.backdropFilter =
    "blur(10px)";

  overlay.style.zIndex = "999999999";

  overlay.style.display = "flex";
  overlay.style.justifyContent = "center";
  overlay.style.alignItems = "center";

  overlay.style.color = "white";

  overlay.style.fontFamily =
    "Arial, sans-serif";

  document.body.appendChild(overlay);

  document
    .getElementById(
      "shadowlink-proceed-btn"
    )
    .addEventListener("click", () => {

      overlay.remove();
    });
}

const result =
  analyzeURL(window.location.href);

const loginIndicators =
  detectLoginForms();

result.indicators.push(
  ...loginIndicators
);

result.score +=
  loginIndicators.length * 20;

result.threatLevel =
  classifyThreat(result.score);

console.log(
  "ShadowLink Analysis:",
  result
);

showWarningBanner(result);

showDangerOverlay(result);

window.shadowLinkData = result;

if (
  result.threatLevel !== "Safe"
) {

  saveThreat(result);
}
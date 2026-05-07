const result =
  analyzeURL(window.location.href);

result.threatLevel =
  classifyThreat(result.score);

console.log(
  "ShadowLink Analysis:",
  result
);

showWarningBanner(result);
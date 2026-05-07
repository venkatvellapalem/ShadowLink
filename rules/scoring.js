function classifyThreat(score) {

  if (score >= 60) {
    return "Dangerous";
  }

  if (score >= 30) {
    return "Suspicious";
  }

  return "Safe";
}
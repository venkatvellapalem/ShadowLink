function classifyThreat(score) {

  if (score >= 50) {
    return "Dangerous";
  }

  if (score >= 25) {
    return "Suspicious";
  }

  return "Safe";
}
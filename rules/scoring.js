function classifyThreat(score) {

  if (score >= 80) {

    return "Dangerous";
  }

  if (score >= 50) {

    return "Suspicious";
  }

  if (score >= 20) {

    return "Warning";
  }

  return "Safe";
}
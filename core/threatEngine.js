function createThreatEngine() {

  return {

    score: 0,

    indicators: [],

    breakdown: [],

    addThreat(points, reason) {

      this.score += points;

      this.indicators.push(reason);

      this.breakdown.push({
        points,
        reason
      });
    }
  };
}
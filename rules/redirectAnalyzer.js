/**
 * redirectAnalyzer.js — Redirect Chain Analysis
 * Analyzes navigation redirect chains for suspicious routing patterns.
 * Data is provided by background.js via window.__slRedirectChain.
 */

/* global suspiciousTLDs */

/**
 * analyzeRedirectChain()
 * @returns {{ score: number, indicators: string[], chain: string[], hopCount: number }}
 */
function analyzeRedirectChain() {
  const result = { score: 0, indicators: [], chain: [], hopCount: 0 };

  try {
    const chain = window.__slRedirectChain || [];
    result.chain = chain;
    result.hopCount = chain.length;

    if (chain.length <= 1) return result; // 0 or 1 hops = normal

    const tlds =
      typeof suspiciousTLDs !== "undefined"
        ? suspiciousTLDs
        : [".xyz", ".top", ".click", ".tk"];

    // Collect unique domains across the chain
    const uniqueDomains = new Set();
    chain.forEach((url) => {
      try {
        uniqueDomains.add(new URL(url).hostname);
      } catch {
        /* ignore unparseable URLs */
      }
    });

    // Score hop count
    if (chain.length >= 5) {
      result.score += 35;
      result.indicators.push(
        `Excessive redirect chain: ${chain.length} hops detected`,
      );
    } else if (chain.length >= 3) {
      result.score += 15;
      result.indicators.push(
        `Multi-hop redirect chain: ${chain.length} hops`,
      );
    }

    // Score hops that pass through suspicious TLDs
    let suspiciousTLDHops = 0;
    chain.forEach((url) => {
      try {
        const h = new URL(url).hostname.toLowerCase();
        if (tlds.some((t) => h.endsWith(t))) suspiciousTLDHops++;
      } catch {
        /* ignore unparseable URLs */
      }
    });

    if (suspiciousTLDHops > 0) {
      result.score += suspiciousTLDHops * 20;
      result.indicators.push(
        `${suspiciousTLDHops} redirect hop(s) through suspicious TLDs`,
      );
    }

    // Score high cross-domain traversal
    if (uniqueDomains.size >= 3) {
      result.score += 10;
      result.indicators.push(
        `Redirect chain crosses ${uniqueDomains.size} different domains`,
      );
    }
  } catch {
    /* silent — never break the caller */
  }

  return result;
}

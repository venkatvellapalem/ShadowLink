async function checkVirusTotal(url) {
  try {
    const response = await fetch(
      `https://shadowlink-api.vercel.app/api/check?url=${encodeURIComponent(url)}`,
    );

    if (!response.ok) {
      console.warn("[ShadowLink] VT API returned:", response.status);
      return null;
    }

    const data = await response.json();
    console.log("[ShadowLink] VT API response:", data);

    // Defensive: extract stats safely
    let stats = null;
    try {
      if (data?.vt?.data?.attributes?.last_analysis_stats) {
        stats = data.vt.data.attributes.last_analysis_stats;
      } else if (data?.vt?.data?.attributes?.stats) {
        stats = data.vt.data.attributes.stats;
      }
    } catch {
      stats = null;
    }

    // Defensive: extract domain age
    let domainAgeDays = null;
    if (typeof data?.domainAgeDays === "number") {
      domainAgeDays = data.domainAgeDays;
    } else if (typeof data?.domain_age_days === "number") {
      domainAgeDays = data.domain_age_days;
    } else if (data?.whois?.creation_date) {
      try {
        const created = new Date(data.whois.creation_date);
        const now = new Date();
        domainAgeDays = Math.floor((now - created) / (1000 * 60 * 60 * 24));
      } catch {
        domainAgeDays = null;
      }
    }

    return { stats, domainAgeDays };
  } catch (error) {
    console.warn("[ShadowLink] VirusTotal check failed:", error);
    return null;
  }
}

async function checkVirusTotal(url) {

  try {

    const controller =
      new AbortController();

    const timeout =
      setTimeout(() => {

        controller.abort();

      }, 10000);

    const response =
      await fetch(

        `https://shadowlink-api.vercel.app/api/check?url=${encodeURIComponent(url)}`,

        {
          signal:
            controller.signal
        }
      );

    clearTimeout(timeout);

    /*
      HTTP error handling
    */

    if (!response.ok) {

      console.warn(

        "[ShadowLink] VT API returned:",

        response.status
      );

      return null;
    }

    /*
      Safe JSON parsing
    */

    let data = null;

    try {

      data =
        await response.json();

    } catch (jsonError) {

      console.warn(

        "[ShadowLink] Invalid JSON response:",

        jsonError
      );

      return null;
    }

    console.log(
      "[ShadowLink] VT API response:",
      data
    );

    /*
      =========================
      Extract VirusTotal stats
      =========================
    */

    let stats = {

      harmless: 0,
      malicious: 0,
      suspicious: 0,
      undetected: 0
    };

    try {

      const vtStats =

        data?.vt?.data?.attributes?.last_analysis_stats

        ||

        data?.vt?.data?.attributes?.stats

        ||

        null;

      if (vtStats) {

        stats = {

          harmless:
            vtStats.harmless || 0,

          malicious:
            vtStats.malicious || 0,

          suspicious:
            vtStats.suspicious || 0,

          undetected:
            vtStats.undetected || 0
        };
      }

    } catch (statsError) {

      console.warn(

        "[ShadowLink] Failed parsing VT stats:",

        statsError
      );
    }

    /*
      =========================
      Extract Domain Age
      =========================
    */

    let domainAgeDays = null;

    try {

      /*
        Direct API value
      */

      if (

        typeof data?.domainAgeDays === "number"

      ) {

        domainAgeDays =
          data.domainAgeDays;
      }

      else if (

        typeof data?.domain_age_days === "number"

      ) {

        domainAgeDays =
          data.domain_age_days;
      }

      /*
        WHOIS fallback
      */

      else if (

        data?.whois?.creation_date

      ) {

        const created =
          new Date(
            data.whois.creation_date
          );

        if (

          !isNaN(created.getTime())

        ) {

          const now =
            new Date();

          domainAgeDays =
            Math.floor(

              (now - created)

              /

              (1000 * 60 * 60 * 24)
            );
        }
      }

    } catch (ageError) {

      console.warn(

        "[ShadowLink] Failed parsing domain age:",

        ageError
      );
    }

    /*
      Final response
    */

    return {

      stats,
      domainAgeDays
    };

  } catch (error) {

    /*
      Abort timeout
    */

    if (

      error.name ===
      "AbortError"

    ) {

      console.warn(
        "[ShadowLink] VT request timeout"
      );
    }

    else {

      console.warn(

        "[ShadowLink] VirusTotal check failed:",

        error
      );
    }

    return null;
  }
}
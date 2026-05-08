async function checkVirusTotal(url) {

  try {

    const response =
      await fetch(

        `https://shadowlink-api.vercel.app/api/check?url=${encodeURIComponent(url)}`

      );

    const data =
      await response.json();

    console.log(
      "VT DATA:",
      data
    );

    return {

      stats:
        data.vt.data.attributes.stats,

      domainAgeDays:
        data.domainAgeDays
    };

  } catch (error) {

    console.log(
      "VirusTotal Error:",
      error
    );

    return null;
  }
}
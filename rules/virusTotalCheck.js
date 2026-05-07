async function checkVirusTotal(url) {

  try {

    const response =
      await fetch(

        `https://shadowlink-api.onrender.com/check?url=${encodeURIComponent(url)}`

      );

    const data =
      await response.json();

    console.log(
      "VT DATA:",
      data
    );

    const stats =
      data.data.attributes.stats;

    return stats;

  } catch (error) {

    console.log(
      "VirusTotal Error:",
      error
    );

    return null;
  }
}
function detectLoginForms() {

  const forms =
    document.querySelectorAll("form");

  let indicators = [];

  const currentHostname =
    window.location.hostname
      .replace("www.", "");

  const isTrusted =
    trustedDomains.some(domain =>
      currentHostname.includes(domain)
    );

  forms.forEach(form => {

    const passwordInputs =
      form.querySelectorAll(
        'input[type="password"]'
      );

    if (passwordInputs.length > 0) {

      // ONLY FLAG if NOT trusted
      if (!isTrusted) {

        indicators.push(
          "Password input field detected"
        );

        const action =
          form.getAttribute("action");

        if (!action || action === "") {

          indicators.push(
            "Form action is suspicious or missing"
          );
        }
      }
    }
  });

  return indicators;
}
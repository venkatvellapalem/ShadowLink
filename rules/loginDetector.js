function detectLoginForms() {

  const forms =
    document.querySelectorAll("form");

  let indicators = [];

  forms.forEach(form => {

    const passwordInputs =
      form.querySelectorAll(
        'input[type="password"]'
      );

    if (passwordInputs.length > 0) {

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
  });

  return indicators;
}
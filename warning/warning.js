const params =
  new URLSearchParams(
    window.location.search
  );

const reason =
  params.get("reason");

document.getElementById(
  "reason"
).innerText =
  reason;

document.getElementById(
  "backBtn"
).onclick = () => {

  history.back();
};
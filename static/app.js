// Confirmation prompts for destructive forms. Lives in a static file because the CSP forbids inline handlers.
document.addEventListener("submit", function (event) {
  var message = event.target.getAttribute("data-confirm");
  if (message && !window.confirm(message)) {
    event.preventDefault();
  }
});

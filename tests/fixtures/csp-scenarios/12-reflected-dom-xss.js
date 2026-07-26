// Scenario: Reflected DOM XSS.
// A URL parameter is read client-side and written into the DOM via a sink, entirely in the
// browser — the server never sees or reflects the value itself.
function displayWelcomeMessage() {
  var name = new URLSearchParams(location.search).get("name");
  document.getElementById("welcome").innerHTML = "Welcome back, " + name + "!";
}

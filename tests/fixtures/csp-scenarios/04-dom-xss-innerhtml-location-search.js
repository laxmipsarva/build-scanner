// Scenario: DOM XSS in innerHTML sink using source location.search.
document.getElementById("results").innerHTML =
  "You searched for: " + decodeURIComponent(location.search.substring(3));

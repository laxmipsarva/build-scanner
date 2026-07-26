// Scenario: DOM XSS in document.write sink using source location.search.
// The query string is written straight into the page via document.write.
function trackSearchTerm() {
  var query = location.search;
  document.write("<img src='/track?q=" + query.substring(3) + "'>");
}

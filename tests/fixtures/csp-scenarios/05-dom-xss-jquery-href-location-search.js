// Scenario: DOM XSS in jQuery anchor href attribute sink using location.search source.
$(function () {
  var returnUrl = decodeURIComponent(/returnUrl=(.*)/.exec(location.search)[1]);
  $("#backLink").attr("href", returnUrl);
});

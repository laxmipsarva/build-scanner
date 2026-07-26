// Scenario: DOM XSS in jQuery selector sink using a hashchange event.
$(window).on("hashchange", function () {
  var post = $("section.blog-list h2:contains(" + decodeURIComponent(location.hash.slice(1)) + ")");
  post.get(0).scrollIntoView();
});

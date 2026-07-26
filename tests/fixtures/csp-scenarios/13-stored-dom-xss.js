// Scenario: Stored DOM XSS.
// A stored value (fetched from the API) is written into the DOM via a sink on page load.
function renderAuthorBio(post) {
  document.getElementById("author-bio").innerHTML = post.authorBio;
}

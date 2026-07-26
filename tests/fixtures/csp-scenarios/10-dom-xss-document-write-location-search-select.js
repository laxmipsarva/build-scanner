// Scenario: DOM XSS in document.write sink using source location.search inside a select element.
function populateStoreDropdown() {
  var stores = location.search;
  document.write('<select name="storeId">' + stores.substring(1) + "</select>");
}

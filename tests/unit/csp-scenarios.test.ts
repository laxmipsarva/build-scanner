import { describe, expect, it } from "vitest";
import rule from "../../src/rules/csp.js";
import { runRule } from "./test-utils.js";

// These fixtures model the PortSwigger Web Security Academy "Cross-site scripting" lab
// scenarios. Almost all of them are XSS *sink* scenarios (document.write, innerHTML, jQuery
// selectors, AngularJS expressions, encoding/escaping bypasses, ...) — build-scanner's
// csp-misconfiguration rule does not do sink-based XSS detection at all; it only inspects the
// text of a Content-Security-Policy configuration itself (unsafe-inline/unsafe-eval, wildcard
// sources, helmet's contentSecurityPolicy disabled). So for the vast majority of these
// scenarios zero findings is the CORRECT, by-design outcome, not a bug — running them
// documents that scope boundary as a permanent regression guard rather than leaving 27 broken
// assertions in the suite. Only scenarios that touch the CSP config text itself can be flagged.
const scenarios: { fixture: string; expectFlagged: boolean; note?: string }[] = [
  { fixture: "01-reflected-xss-html-nothing-encoded.js", expectFlagged: false },
  { fixture: "02-stored-xss-html-nothing-encoded.js", expectFlagged: false },
  { fixture: "03-dom-xss-document-write-location-search.js", expectFlagged: false },
  { fixture: "04-dom-xss-innerhtml-location-search.js", expectFlagged: false },
  { fixture: "05-dom-xss-jquery-href-location-search.js", expectFlagged: false },
  { fixture: "06-dom-xss-jquery-selector-hashchange.js", expectFlagged: false },
  { fixture: "07-reflected-xss-attribute-angle-brackets-encoded.js", expectFlagged: false },
  { fixture: "08-stored-xss-anchor-href-double-quotes-encoded.js", expectFlagged: false },
  { fixture: "09-reflected-xss-js-string-angle-brackets-encoded.js", expectFlagged: false },
  { fixture: "10-dom-xss-document-write-location-search-select.js", expectFlagged: false },
  { fixture: "11-dom-xss-angularjs-expression-encoded.js", expectFlagged: false },
  { fixture: "12-reflected-dom-xss.js", expectFlagged: false },
  { fixture: "13-stored-dom-xss.js", expectFlagged: false },
  { fixture: "14-reflected-xss-most-tags-attributes-blocked.js", expectFlagged: false },
  { fixture: "15-reflected-xss-all-tags-blocked-except-custom.js", expectFlagged: false },
  { fixture: "16-reflected-xss-svg-markup-allowed.js", expectFlagged: false },
  { fixture: "17-reflected-xss-canonical-link-tag.js", expectFlagged: false },
  { fixture: "18-reflected-xss-js-string-single-quote-backslash-escaped.js", expectFlagged: false },
  { fixture: "19-reflected-xss-js-string-encoded-and-escaped.js", expectFlagged: false },
  { fixture: "20-stored-xss-onclick-encoded-and-escaped.js", expectFlagged: false },
  { fixture: "21-reflected-xss-template-literal-unicode-escaped.js", expectFlagged: false },
  { fixture: "22-exploiting-xss-steal-cookies.js", expectFlagged: false },
  { fixture: "23-exploiting-xss-capture-passwords.js", expectFlagged: false },
  { fixture: "24-exploiting-xss-bypass-csrf-defenses.js", expectFlagged: false },
  { fixture: "25-reflected-xss-angularjs-sandbox-escape-without-strings.js", expectFlagged: false },
  {
    fixture: "26-reflected-xss-angularjs-sandbox-escape-and-csp.js",
    expectFlagged: true,
    note: "CSP allows 'unsafe-eval', which the rule does check for",
  },
  { fixture: "27-reflected-xss-event-handlers-href-blocked.js", expectFlagged: false },
  { fixture: "28-reflected-xss-js-url-some-characters-blocked.js", expectFlagged: false },
  {
    fixture: "29-reflected-xss-strict-csp-dangling-markup.js",
    expectFlagged: true,
    note: "script-src is strict, but img-src * is the actual misconfig enabling exfiltration",
  },
  {
    fixture: "30-reflected-xss-csp-bypass.js",
    expectFlagged: false,
    note: "known-bypass allowlisted domain — no unsafe-inline/eval or wildcard, so this rule can't see it",
  },
];

describe("csp-misconfiguration rule vs. XSS attack scenarios (scope-boundary documentation)", () => {
  it.each(scenarios)(
    "$fixture — expectFlagged=$expectFlagged",
    ({ fixture, expectFlagged }) => {
      const findings = runRule(rule, `csp-scenarios/${fixture}`);
      expect(findings.length > 0).toBe(expectFlagged);
    },
  );
});

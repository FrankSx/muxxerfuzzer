# VENDOR.md — third-party library pins

The fuzzer's sanitizer matrix runs against real libraries. Minified copies
are **not committed** (they're large and unreviewable as diffs); instead
`harness.html` pulls each one at load time from jsDelivr, pinned to the
exact version under test. If a lib is unreachable its engine reports
`N/A` and the rest of the matrix keeps running.

| lib | version | file the harness expects | CDN URL (pinned) | license | upstream |
|---|---|---|---|---|---|
| DOMPurify | 3.2.5 | `js/purify.min.js` | https://cdn.jsdelivr.net/npm/dompurify@3.2.5/dist/purify.min.js | Apache-2.0 / MPL-2.0 | github.com/cure53/DOMPurify |
| js-xss | 1.0.15 | `js/xss.min.js` | https://cdn.jsdelivr.net/npm/xss@1.0.15/dist/xss.min.js | MIT | github.com/leizongmin/js-xss |
| marked | 15.0.7 | `js/marked.min.js` | https://cdn.jsdelivr.net/npm/marked@15.0.7/marked.min.js | MIT | github.com/markedjs/marked |
| jQuery (slim) | 3.7.1 | `js/jquery.slim.min.js` | https://cdn.jsdelivr.net/npm/jquery@3.7.1/dist/jquery.slim.min.js | MIT | github.com/jquery/jquery |
| AngularJS | 1.8.3 | `js/angular.min.js` | https://cdn.jsdelivr.net/npm/angular@1.8.3/angular.min.js | MIT | github.com/angular/angular.js |
| angular-sanitize | 1.8.3 | `js/angular-sanitize.min.js` | https://cdn.jsdelivr.net/npm/angular-sanitize@1.8.3/angular-sanitize.min.js | MIT | github.com/angular/angular.js |

## Running fully offline

1. Download each file above into `js/` under the listed filename.
2. In `harness.html`, point the six CDN `<script>` tags back at the local
   paths (`js/purify.min.js`, …).
3. Serve locally as usual: `python3 tools/runner.py serve`.

## Version discipline

The engine names in `js/sanitizer.js` hard-code these versions
(`DOMPurify 3.2.5`, `js-xss 1.0.15`, `Angular $sanitize 1.8.3`) because
bounty reports must pin the exact version that falls. If you bump a pin,
update the engine name too — a bypass against the wrong version label is
a wasted report.

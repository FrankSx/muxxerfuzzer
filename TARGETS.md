# TARGETS.md — mXSS Bounty Playbook

How to turn fuzzer output into paid reports. Order of payout class:
**browser CVE > library CVE > app-specific bug**.

---

## 1. Engine → disclosure channel

| engine id | library | report to | class |
|---|---|---|---|
| `dp` / `dpt` | DOMPurify (Cure53) | GitHub Security Advisory on the repo | library CVE |
| `jsxss` | js-xss / npm `xss` | GitHub Security Advisory (leizongmin/js-xss) | library CVE |
| `shtml` | sanitize-html (ApostropheCMS) | GitHub Security Advisory (apostrophecms/sanitize-html) | library CVE |
| `native` | W3C Sanitizer API | Chromium VRP / Mozilla Client Bug Bounty | **browser CVE** |
| `regex` | home-grown filters | whatever program owns the app | app bug |

The export JSON carries a `programs[]` block with this mapping, and
`runner.py report` prints the matching channel under each bypass.

## 2. Fingerprinting sanitizers in a scoped target

Before claiming "app X uses engine Y", verify:

```js
// console, on the target origin
window.DOMPurify && DOMPurify.version          // library + version
document.querySelector('script[src*="purify"]')?.src
document.querySelector('script[src*="xss"]')?.src
typeof Sanitizer !== "undefined"               // native API presence
```

- View-source / devtools network for `purify.min.js`, `xss.min.js`,
  `sanitize-html` (server-side — look for its *behavioral* signature:
  output attribute order, `&amp;` style, tag case)
- sanitize-html is server-side: feed the app a canary string like
  `<b data-fz="1">x</b>` and compare the returned HTML to a local
  sanitize-html default run — attribute quoting/ordering is distinctive
- Exposed `package.json` / `yarn.lock` / source maps leak exact versions
- DOMPurify config detection: SAFE_FOR_TEMPLATES swaps `{{`-style mustaches
  for comments — probe with `{{x}}`

## 3. Where these engines typically sit (pattern level)

- **Webmail / ticketing / CRM render paths** — HTML email sanitization is
  the classic mXSS hunting ground (message preview = sanitize + innerHTML)
- **Comment / forum / markdown pipelines** — md → html → sanitize → render
- **Admin dashboards** — stored-XSS surface, often weaker review
- **WYSIWYG editors** — they *are* mutation engines; paste paths reparse
- **PDF/export pipelines** — server-side reparse of "sanitized" HTML

Match the app's observed sanitizer fingerprint to the fuzzer engine id,
then run the fuzzer in targeted mode against that engine's profile.

## 4. Report quality checklist

1. **Minimal PoC** — run `ddmin[engine]` on the hit; attach the shrunk
   string, not the 900-char fuzz blob
2. **Version pin** — exact library version (and config) that falls
3. **Concrete sink** — show the bypass reaching an *executable* context:
   a page that does `el.innerHTML = sanitize(untrusted)` is the whole story
4. **Reparse evidence** — for s-mXSS, include both serializations
   (post-sanitize vs post-reparse) — the +N script-surface diff is the proof
5. **Canary ≠ alert()** — our `__mxss.hit()` canaries are postMessage-based;
   swap to `alert(document.domain)` only for the final report PoC
6. One engine per report; don't bundle libraries

## 5. Severity framing (CVSS-ish guidance)

| finding | typical framing |
|---|---|
| library mXSS bypass with real-world sink | stored XSS via library — High |
| native Sanitizer API bypass | browser security — Critical class |
| regex/home-grown filter bypass in scoped app | stored XSS — Med/High |
| double-decode (text:BYPASS) needing weird re-insert | app-specific — Med, explain the sink |

## 6. Ethics / scope

- Only test engines against **in-scope** programs. Library maintainers
  generally accept PoCs via advisory; browser vendors have formal programs.
- The fuzzer is local and offline — it never touches a third party.
  Verification against a scoped app is on you: stay in scope, no stored
  payloads on shared/staging systems without permission.

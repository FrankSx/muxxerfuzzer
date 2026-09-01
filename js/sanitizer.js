/* ============================================================================
 * sanitizer.js — cross-engine sanitizer matrix (v4.1 merged)
 *
 * Engines carry `program` metadata: the disclosure channel + payout class
 * for whichever target survives. Oracles per engine:
 *
 *   pass-through : critical surface still present after sanitize()
 *                  -> SANBYPASS bit
 *   reparse-grow : critical surface absent after sanitize(), but appears
 *                  when the sanitized serialization is REPARSED
 *                  -> SMXSS bit (true sanitizer mutation-XSS)
 *
 * Libraries load from version-pinned CDN URLs (see VENDOR.md); engines
 * report N/A when their library is unreachable, the matrix keeps running.
 * sanitize-html is intentionally absent: it ships no browser bundle
 * (Node-only). Feeding it via a bundler is server-side terrain; the
 * differential vs browser parsers remains on the roadmap.
 * ========================================================================== */
"use strict";
const Sanitizer = (() => {
  const dp = () => (typeof DOMPurify !== "undefined") ? DOMPurify : null;
  const fx = () => (typeof filterXSS !== "undefined") ? filterXSS : null;
  const jq = () => (typeof jQuery !== "undefined") ? jQuery : null;
  const mk = () => (typeof marked !== "undefined") ? marked : null;
  const ng = () => (typeof angular !== "undefined" && angular.injector) ? angular : null;

  let _ngSanitize = null;
  function ngSanitize() {
    if (!_ngSanitize && ng()) {
      try { _ngSanitize = ng().injector(["ng", "ngSanitize"]).get("$sanitize"); }
      catch (e) { _ngSanitize = null; }
    }
    return _ngSanitize;
  }

  /* native Sanitizer API — window.Sanitizer, NOT our module const (shadow bug) */
  function nativeAvailable() {
    return typeof window.Sanitizer !== "undefined"
        || (typeof Element !== "undefined" && "setHTML" in Element.prototype);
  }
  function nativeSanitize(s) {
    if (!nativeAvailable()) return "[n/a]";
    const el = document.createElement("div");
    try { el.setHTML(s); }
    catch (e) {
      try { el.setHTML(s, { sanitizer: new window.Sanitizer() }); }
      catch (e2) { return "[n/a]"; }
    }
    return el.innerHTML;
  }

  const ENGINES = [
    { id: "none",   name: "None",
      program: null,
      fn: s => s },
    { id: "dp",     name: "DOMPurify 3.2.5",
      program: { vendor: "Cure53", channel: "GitHub Security Advisory (cure53/DOMPurify)",
                 klass: "library CVE", note: "rich mXSS CVE history; bypasses taken seriously" },
      fn: s => dp() ? dp().sanitize(s) : "[n/a]" },
    { id: "dpt",    name: "DOMPurify+TEMPL",
      program: { vendor: "Cure53", channel: "GitHub Security Advisory (cure53/DOMPurify)",
                 klass: "library CVE", note: "SAFE_FOR_TEMPLATES config" },
      fn: s => dp() ? dp().sanitize(s, { SAFE_FOR_TEMPLATES: true }) : "[n/a]" },
    { id: "dps",    name: "DOMPurify STRICT",
      program: null,
      fn: s => dp() ? dp().sanitize(s, { ALLOWED_TAGS: ["b","i","u","em","strong"],
                                         ALLOWED_ATTR: [] }) : "[n/a]" },
    { id: "jsxss",  name: "js-xss 1.0.15",
      program: { vendor: "leizongmin", channel: "GitHub Security Advisory (leizongmin/js-xss) / npm xss",
                 klass: "library CVE", note: "allowlist filter engine, big in Node ecosystems" },
      fn: s => fx() ? fx()(s) : "[n/a]" },
    { id: "ngsan",  name: "Angular $sanitize 1.8.3",
      program: { vendor: "Google (AngularJS)", channel: "GitHub Security Advisory (angular/angular.js)",
                 klass: "library CVE", note: "legacy AngularJS still embedded everywhere; token-based sanitizer" },
      fn: s => ngSanitize() ? ngSanitize()(s) : "[n/a]" },
    { id: "native", name: "Sanitizer API",
      program: { vendor: "W3C/browser vendors", channel: "Chromium VRP / Mozilla Client Bug Bounty",
                 klass: "browser CVE — highest payout class",
                 note: "native setHTML(); spec still young, parser-differential bugs plausible" },
      fn: nativeSanitize },
    { id: "jqhtml", name: "jQuery .html() sink",
      program: { vendor: "jQuery + every app using $.html()", channel: "GitHub Security Advisory (jquery/jquery) / app scope",
                 klass: "sink CVE + app bug", note: "htmlPrefilter+manipulation path; models $('#x').html(userInput) sinks" },
      fn: s => jq() ? jq()("<div>").html(s).html() : "[n/a]" },
    { id: "mdpipe", name: "Markdown→DOMPurify pipe",
      program: { vendor: "marked + downstream apps", channel: "GitHub Security Advisory (markedjs/marked) / app scope",
                 klass: "library CVE + app bug", note: "comment fields everywhere: GitLab, forums, CMS preview panes" },
      fn: s => (mk() && dp()) ? dp().sanitize(mk().parse(s, { async: false })) : "[n/a]" },
    { id: "regex",  name: "Naive Regex",
      program: { vendor: "every app ever", channel: "app-specific bounty scope",
                 klass: "app bug", note: "stands in for home-grown filters found in the wild" },
      fn: s => s.replace(/<script\b[^<]*(?:(?!<\/script>)<[^<]*)*<\/script>/gi, "")
                .replace(/javascript:/gi, "")
                .replace(/on\w+\s*=\s*["']?[^"'>]*["']?/gi, "") },
    { id: "text",   name: "Text-only",
      program: null,
      fn: s => { const d = document.createElement("div"); d.innerHTML = s;
                 return d.textContent || ""; } }
  ];

  /* static signal scan — structure-preserving (no execution) */
  function detect(html) {
    const signals = [];
    if (typeof html !== "string" || html === "[n/a]") return signals;
    const div = document.createElement("div");
    try { div.innerHTML = html; } catch (e) { return signals; }
    const push = (type, severity, detail) => signals.push({ type, severity, detail });

    if (div.querySelector("script")) push("SCRIPT", "critical", "<script> in DOM");
    for (const el of div.querySelectorAll("*")) {
      const tag = el.tagName.toLowerCase();
      for (const attr of el.attributes) {
        const an = attr.name.toLowerCase(), av = attr.value;
        if (/^on\w+/i.test(attr.name)) push("EVENT", "critical", attr.name + " on " + tag);
        /* browsers strip tab/LF/CR from URL schemes before matching — normalize first */
        const avNorm = av.replace(/[\t\n\r ]+/g, "");
        if (/javascript:|vbscript:/i.test(avNorm)) push("PROTOCOL", "critical", "js-url in " + an);
        if (/^\s*data:/i.test(av) && an !== "srcdoc") push("DATA_URI", "warning", "data: in " + an);
        if (an === "srcdoc") push("SRCDOC", "warning", "srcdoc on " + tag);
        if (an === "formaction" || an === "xlink:href") push("FORMHIJACK", "warning", an + " on " + tag);
      }
      if (tag === "meta" && /refresh/i.test(el.getAttribute("http-equiv") || ""))
        push("META", "critical", "meta refresh");
    }
    if (div.querySelector("svg"))  push("SVG", "warning", "<svg> present");
    if (div.querySelector("math")) push("MATHML", "warning", "<math> present");
    if (div.querySelector("foreignobject")) push("FOREIGN", "warning", "<foreignObject> present");
    if (div.querySelector("template"))      push("TEMPLATE", "warning", "<template> present");
    if (div.querySelector("iframe"))        push("IFRAME", "warning", "<iframe> present");
    const fmt = ["b","i","u","s","strike","big","small","tt","a","font","nobr","em","strong"];
    for (const t of fmt) {
      const els = div.querySelectorAll(t);
      if (els.length > 1) {
        for (const el of els) {
          const p = el.parentElement;
          if (p && fmt.includes(p.tagName.toLowerCase())) {
            push("ADOPTION", "info", "overlap " + t + " in " + p.tagName.toLowerCase());
            break;
          }
        }
      }
    }
    for (const table of div.querySelectorAll("table"))
      for (const child of table.children)
        if (!["TBODY","THEAD","TFOOT","CAPTION","COLGROUP","TR"].includes(child.tagName))
          push("FOSTER", "info", child.tagName + " fostered in <table>");
    return signals;
  }

  const crits = sigs => sigs.filter(s => s.severity === "critical").map(s => s.type);

  /** analyze one engine against one candidate (oracle primitive) */
  function analyze(engine, html) {
    let sanitized;
    try { sanitized = engine.fn(html); } catch (err) { sanitized = "[error] " + err.message; }
    if (sanitized === "[n/a]") return { verdict: "N/A", critical: [], reparseCritical: [], sanitized };
    const sigs = detect(sanitized);
    const crit = crits(sigs);
    let reparseCrit = [];
    try {
      const d1 = document.createElement("div");
      d1.innerHTML = sanitized;
      reparseCrit = crits(detect(d1.innerHTML)).filter(t => !crit.includes(t));
    } catch (err) {}
    let verdict = "CLEAN";
    if (crit.length) verdict = "BYPASS";
    else if (reparseCrit.length && engine.id !== "none" && engine.id !== "text") verdict = "mXSS";
    else if (sigs.some(s => s.severity === "warning")) verdict = "WARN";
    return { verdict, critical: crit, reparseCritical: reparseCrit, sanitized };
  }

  /**
   * matrix(html) -> { engines:[{id,name,verdict,...}], bits, summary }
   */
  function matrix(html) {
    const V = MXSSState.V;
    let bits = 0;
    const engines = [];
    for (const e of ENGINES) {
      const a = analyze(e, html);
      if (a.verdict === "BYPASS" && e.id !== "none") bits |= V.SANBYPASS;
      if (a.verdict === "mXSS") bits |= V.SMXSS;
      engines.push({ id: e.id, name: e.name, verdict: a.verdict,
                     critical: a.critical, reparseCritical: a.reparseCritical,
                     warnings: 0, sanitized: a.sanitized });
    }
    const summary = engines.map(e => e.id + ":" + e.verdict).join(" ");
    return { engines, bits, summary };
  }

  const engineById = id => ENGINES.find(e => e.id === id);

  /** oracleFor(engineId, wantVerdict) -> async html => bool (minimizer food) */
  function oracleFor(engineId, want) {
    const eng = engineById(engineId);
    if (!eng) return async () => false;
    return async html => analyze(eng, html).verdict === want;
  }

  /** programs() — disclosure channels for engines that have them */
  function programs() {
    return ENGINES.filter(e => e.program).map(e => Object.assign({ id: e.id, name: e.name }, e.program));
  }

  /* severity scoring for hunt automation (higher = worse for the sanitizer) */
  const VERDICT_SCORE = { "CLEAN": 0, "WARN": 1, "mXSS": 2, "BYPASS": 3, "N/A": -1 };
  function score(html, engineIds) {
    let best = 0;
    for (const id of engineIds) {
      const e = engineById(id);
      if (!e) continue;
      best = Math.max(best, VERDICT_SCORE[analyze(e, html).verdict] || 0);
    }
    return best;
  }

  return { ENGINES, detect, matrix, analyze, engineById, oracleFor, programs,
           score, VERDICT_SCORE };
})();
if (typeof module !== "undefined") module.exports = Sanitizer;

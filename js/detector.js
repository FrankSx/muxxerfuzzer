/* ============================================================================
 * detector.js — differential HTML5 parser verdict engine
 *
 * Parses a candidate through three independent host parse paths
 * (div.innerHTML / template.innerHTML / DOMParser), canonicalizes the
 * resulting trees, then reparses the serialization — the classic
 * mutation-XSS oracles:
 *
 *   round-trip instability  -> parser mutates the input
 *   script-capable growth   -> the mutation CREATED execution surface
 *   namespace drift         -> foreign-content pivot happened
 * ========================================================================== */
"use strict";
const Detector = (() => {
  const V = () => MXSSState.V;
  const EVT_ATTR  = /^on/i;
  const URL_ATTR  = new Set(["href","src","action","formaction","xlink:href",
                             "data","poster","background","cite","longdesc"]);
  const RAWTEXT   = new Set(["style","xmp","iframe","noembed","noframes","plaintext"]);
  const RCDATA    = new Set(["title","textarea"]);
  const TABLEY    = new Set(["table","thead","tbody","tfoot","tr","td","th","caption","colgroup"]);

  function parseDiv(html)      { const d = document.createElement("div"); d.innerHTML = html; return d; }
  function parseTemplate(html) { const t = document.createElement("template"); t.innerHTML = html; return t.content; }
  function parseDP(html)       { return new DOMParser().parseFromString(html, "text/html"); }

  /* canonical serialization: tag + sorted attrs + children, ns-aware */
  function canon(node, depth, out) {
    if (node.nodeType === 3) { out.push("#t:" + node.nodeValue); return; }
    if (node.nodeType === 8) { out.push("<!--" + node.nodeValue + "-->"); return; }
    if (node.nodeType !== 1 && node.nodeType !== 11 && node.nodeType !== 9) return;
    if (node.nodeType === 1) {
      const el = node, ns = el.namespaceURI || "";
      let attrs = [];
      for (const a of el.attributes) attrs.push(a.name + "=" + JSON.stringify(a.value));
      attrs.sort();
      out.push("<".repeat(1) + (ns.includes("svg") ? "s:" : ns.includes("math") ? "m:" : "h:")
               + el.localName + " " + attrs.join(" "));
    }
    const kids = node.childNodes || (node.content && node.content.childNodes) || [];
    for (const k of kids) canon(k, depth + 1, out);
    if (node.nodeType === 1) out.push("/" + node.localName);
  }
  const canonical = root => { const o = []; canon(root, 0, o); return o.join("\n"); };

  /* count execution-capable constructs in a tree */
  function scriptSurface(root) {
    const hits = [];
    const walk = n => {
      if (n.nodeType === 1) {
        const el = n, tag = el.localName.toLowerCase();
        if (tag === "script" || tag === "iframe" || tag === "object" || tag === "embed"
            || tag === "applet" || tag === "frame" || tag === "frameset")
          hits.push("tag:" + tag);
        if (tag === "meta" && /refresh/i.test(el.getAttribute("http-equiv") || ""))
          hits.push("meta:refresh");
        if (tag === "base" && el.getAttribute("href")) hits.push("base:href");
        if (tag === "link" && /stylesheet|import|preload/i.test(el.getAttribute("rel") || ""))
          hits.push("link:" + (el.getAttribute("rel") || ""));
        for (const a of el.attributes) {
          if (EVT_ATTR.test(a.name)) hits.push("evt:" + tag + "." + a.name);
          if (URL_ATTR.has(a.name.toLowerCase()) &&
              /^\s*(javascript|data|vbscript)\s*:/i.test(a.value))
            hits.push("url:" + tag + "[" + a.name + "]");
          if (a.name.toLowerCase() === "srcdoc") hits.push("srcdoc:" + tag);
        }
      }
      const kids = n.childNodes || (n.content && n.content.childNodes) || [];
      for (const k of kids) walk(k);
    };
    walk(root);
    return hits;
  }

  function nsHistogram(root) {
    const h = { h: 0, s: 0, m: 0 };
    const walk = n => {
      if (n.nodeType === 1) {
        const ns = n.namespaceURI || "";
        h[ns.includes("svg") ? "s" : ns.includes("math") ? "m" : "h"]++;
      }
      const kids = n.childNodes || (n.content && n.content.childNodes) || [];
      for (const k of kids) walk(k);
    };
    walk(root);
    return h;
  }

  const hasTag = (root, set) => {
    let found = null;
    const walk = n => {
      if (found) return;
      if (n.nodeType === 1 && set.has(n.localName.toLowerCase())) { found = n.localName; return; }
      const kids = n.childNodes || (n.content && n.content.childNodes) || [];
      for (const k of kids) walk(k);
    };
    walk(root);
    return found;
  };

  /**
   * differential(html) -> { bits, notes, canon1, canon2, surface1, surface2 }
   * round 1: parse candidate  |  round 2: reparse its innerHTML serialization
   */
  function differential(html) {
    let bits = 0; const notes = [];
    const Vv = V();

    const d1 = parseDiv(html);
    const c1 = canonical(d1);
    let ser1;
    try { ser1 = d1.innerHTML; } catch (e) { ser1 = c1; }
    const d2 = parseDiv(ser1);
    const c2 = canonical(d2);

    const s1 = scriptSurface(d1), s2 = scriptSurface(d2);

    if (c1 !== c2) { bits |= Vv.DIVERGE; notes.push("round-trip serialization unstable"); }
    if (s2.length > s1.length) {
      bits |= Vv.NEWSCRIPT;
      notes.push("reparse GREW script surface: +" + (s2.length - s1.length)
                 + " [" + s2.filter(x => !s1.includes(x)).slice(0, 4).join(", ") + "]");
    }
    const h1 = nsHistogram(d1), h2 = nsHistogram(d2);
    if (h1.s !== h2.s || h1.m !== h2.m) { bits |= Vv.NSPIVOT; notes.push("namespace drift between reparses"); }

    if (bits & Vv.DIVERGE) {
      if (hasTag(d1, TABLEY) || hasTag(d2, TABLEY)) { bits |= Vv.FOSTER;  notes.push("table context involved (foster-parenting candidate)"); }
      const rt = hasTag(d2, RAWTEXT) || hasTag(d2, RCDATA);
      if (rt) { bits |= Vv.RAWTEXT; notes.push("rawtext/rcdata element in tree: " + rt); }
    }
    if (/&#|&NewLine|&Tab|�/.test(ser1) || /&#|&NewLine|&Tab|�/.test(html))
      { bits |= Vv.ENCODE; notes.push("entity/replacement-char signature present"); }

    /* cross-path disagreement: template vs div vs DOMParser */
    try {
      const ct = canonical(parseTemplate(html));
      const cd = canonical(parseDP(html).body || parseDP(html));
      if (ct !== c1) notes.push("template path disagrees with div path");
      if (cd !== c1) notes.push("DOMParser path disagrees with div path");
    } catch (e) { notes.push("cross-path parse error: " + e.message); }

    return { bits, notes, canon1: c1, canon2: c2, surface1: s1, surface2: s2 };
  }

  return { differential, scriptSurface, canonical, parseDiv };
})();
if (typeof module !== "undefined") module.exports = Detector;

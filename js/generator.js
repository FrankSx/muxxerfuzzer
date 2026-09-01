/* ============================================================================
 * generator.js — generational payload engine (v3.0 lineage, v4.0 fixes)
 *
 * Builds random DOM trees with hostile attributes + injects known-bad
 * structural patterns, then optionally entity/invisible-encodes the result.
 *
 * Fixes vs v3.0:
 *   - Park-Miller zero-trap gone: driven by MutEngine.mulberry32 (seeded,
 *     reproducible, never locks at 0)
 *   - payloads carry __mxss.hit() canaries instead of alert() — alert is a
 *     no-op in sandboxed iframes; canaries actually report execution
 *   - generate() returns { html, opsApplied } so the harness treats
 *     generation and mutation uniformly
 * ========================================================================== */
"use strict";
const Generator = (() => {
  const TAGS = {
    normal: ["div","span","p","b","i","u","s","em","strong","a","img","br","hr",
             "h1","h2","h3","ul","li","table","tr","td","th","form","input",
             "button","label","textarea","select","option"],
    script: ["script","noscript","template","xmp","plaintext","iframe","object",
             "embed","math","svg","foreignObject","style","title"],
    adoption: ["b","i","u","s","strike","big","small","tt","a","font","nobr","em","strong"],
    void: ["img","br","hr","input","embed","meta","link","area","base","col",
           "param","source","track","wbr"]
  };
  const ATTRIBUTES = {
    normal: ["id","class","style","title","name","value","type","href","src",
             "alt","width","height"],
    event: ["onerror","onload","onclick","onfocus","onmouseover","onmouseenter",
            "oninput","onchange","onsubmit","onkeydown","onanimationstart",
            "ontransitionend","onpageshow"],
    dangerous: ["srcdoc","action","formaction","poster","background","xmlns"]
  };
  const PROTOCOLS = ["javascript:","data:","vbscript:","file:","about:","blob:"];
  const CANARY = id => "__mxss.hit('" + id + "')";
  const INVISIBLE = ["\u200b","\u200c","\u200d","\u200e","\u200f","\u2060","\u2061","\u2062","\u2063","\u2064","\ufeff","\u00a0","\u2028","\u2029"];

  const pick  = (rng, arr) => arr[Math.floor(rng() * arr.length)];
  const bool  = (rng, p) => rng() < p;
  const randInt = (rng, a, b) => a + Math.floor(rng() * (b - a + 1));

  function encodeEntity(rng, ch, noSemi) {
    const cp = ch.codePointAt(0);
    if (noSemi && cp < 128) {
      const map = { 60:"&lt", 62:"&gt", 38:"&amp", 34:"&quot", 39:"&apos", 160:"&nbsp" };
      if (map[cp]) return map[cp];
    }
    return "&#" + cp + (bool(rng, 0.15) ? "" : ";");   // sometimes drop the semicolon
  }
  function encodeString(rng, str, cfg) {
    let out = "";
    for (const ch of str) {
      if (bool(rng, cfg.invisProb)) out += pick(rng, INVISIBLE);
      out += bool(rng, cfg.entityProb) ? encodeEntity(rng, ch, bool(rng, cfg.noSemiProb)) : ch;
    }
    return out;
  }

  /* structural pattern library — every armed pattern carries a canary */
  function patterns(cfg) {
    const P = [];
    if (cfg.useAdopt) {
      P.push({ id: "gen-adopt-1", html: "<p><b><i><b></b></i></b></p>" });
      P.push({ id: "gen-adopt-2", html: "<div><a><div><img src=x onerror=" + CANARY("gen-adopt-2") + "></div></a></div>" });
    }
    if (cfg.useMath) {
      P.push({ id: "gen-math-1", html: "<math><mtext><table><mglyph><style><img src=x onerror=" + CANARY("gen-math-1") + ">" });
      P.push({ id: "gen-math-2", html: "<math><mtext><table><mglyph><style><!--</style><img title=\"--><img src=1 onerror=" + CANARY("gen-math-2") + ">\">" });
    }
    if (cfg.useSVG) {
      P.push({ id: "gen-svg-1", html: "<svg><foreignObject><body xmlns=\"http://www.w3.org/1999/xhtml\"><script>" + CANARY("gen-svg-1") + "</script></body></foreignObject></svg>" });
      P.push({ id: "gen-svg-2", html: "<svg onload=" + CANARY("gen-svg-2") + ">" });
      P.push({ id: "gen-svg-3", html: "<svg><p><style><!--</style>--></style></p></svg>" });
    }
    if (cfg.useTemplate) {
      P.push({ id: "gen-tpl-1", html: "<template><script>" + CANARY("gen-tpl-1") + "</script></template>" });
      P.push({ id: "gen-tpl-2", html: "<table><template><tr><td><img src=x onerror=" + CANARY("gen-tpl-2") + "></td></tr></template></table>" });
    }
    if (cfg.useNoscript) {
      P.push({ id: "gen-nos-1", html: "<noscript><p title=\"</noscript><img src=x onerror=" + CANARY("gen-nos-1") + ">\">" });
    }
    if (cfg.useXMP) {
      P.push({ id: "gen-xmp-1", html: "<xmp><img src=x onerror=" + CANARY("gen-xmp-1") + "></xmp>" });
      P.push({ id: "gen-xmp-2", html: "</xmp><img src=x onerror=" + CANARY("gen-xmp-2") + "><xmp>" });
    }
    if (cfg.useClobber) {
      P.push({ id: "gen-clob-1", html: "<form name=\"__mxss\"><input name=\"hit\"></form>" });
      P.push({ id: "gen-clob-2", html: "<img name=\"document\"><img name=\"cookie\">" });
    }
    if (cfg.useNS) {
      P.push({ id: "gen-ns-1", html: "<math><style><img src=x onerror=" + CANARY("gen-ns-1") + "></style></math>" });
      P.push({ id: "gen-ns-2", html: "<svg><desc><script>" + CANARY("gen-ns-2") + "</script></desc></svg>" });
    }
    if (cfg.useComment) {
      P.push({ id: "gen-com-1", html: "<!--><img src=x onerror=" + CANARY("gen-com-1") + "><!-->" });
      P.push({ id: "gen-com-2", html: "<!-- --!><img src=x onerror=" + CANARY("gen-com-2") + "><!-- -->" });
    }
    if (cfg.useMarkdown) {
      /* markdown-pipe terrain: links, images, autolinks, raw-html passthrough */
      P.push({ id: "gen-md-1", md: true, html: "[click](javascript:" + CANARY("gen-md-1") + ")" });
      P.push({ id: "gen-md-2", md: true, html: "![i](x) [t](data:text/html,<script>" + CANARY("gen-md-2") + "</script>)" });
      P.push({ id: "gen-md-3", md: true, html: "[x](&#106;avascript:" + CANARY("gen-md-3") + ")" });
      P.push({ id: "gen-md-4", md: true, html: "<math><mtext><table><mglyph><style><!--</style><img title=\"--><img src=1 onerror=" + CANARY("gen-md-4") + ">\">" });
      P.push({ id: "gen-md-5", md: true, html: "[a](url \"title\") <svg onload=" + CANARY("gen-md-5") + ">" });
    }
    return P;
  }

  function genNode(rng, cfg, d) {
    if (d <= 0) return encodeString(rng, pick(rng, ["test","x","click","1",""]), cfg);
    const pool = [...TAGS.normal];
    if (bool(rng, 0.2)) pool.push(...TAGS.script);
    if (cfg.useAdopt && bool(rng, 0.3)) pool.push(...TAGS.adoption);
    const tag = pick(rng, pool);
    if (TAGS.void.includes(tag)) return "<" + tag + genAttrs(rng, cfg) + ">";

    let kids = "";
    const n = randInt(rng, 0, cfg.maxChildren);
    for (let i = 0; i < n; i++) kids += genNode(rng, cfg, d - 1);
    return "<" + tag + genAttrs(rng, cfg) + ">" + kids + "</" + tag + ">";
  }

  function genAttrs(rng, cfg) {
    let out = "";
    const n = randInt(rng, 0, 3);
    for (let i = 0; i < n; i++) {
      const pool = [...ATTRIBUTES.normal];
      if (bool(rng, 0.4)) pool.push(...ATTRIBUTES.event);
      if (bool(rng, 0.2)) pool.push(...ATTRIBUTES.dangerous);
      const attr = pick(rng, pool);
      let val;
      if (["src","href","action","formaction","poster","background"].includes(attr))
        val = pick(rng, PROTOCOLS) + CANARY("gen-url");
      else if (attr.startsWith("on"))
        val = CANARY("gen-evt-" + attr.slice(2));
      else if (attr === "srcdoc")
        val = "<img src=x onerror=&quot;" + CANARY("gen-srcdoc") + "&quot;>";
      else
        val = encodeString(rng, pick(rng, ["test","x","1","click"]), cfg);
      out += " " + attr + "=\"" + val + "\"";
    }
    return out;
  }

  const DEFAULTS = {
    depth: 4, maxChildren: 3,
    entityProb: 0.30, noSemiProb: 0.15, invisProb: 0.10,
    useAdopt: true, useMath: true, useSVG: true, useTemplate: true,
    useNoscript: true, useXMP: true, useClobber: true, useNS: true, useComment: true,
    useMarkdown: false
  };

  /**
   * generate(rng, cfg) -> { html, opsApplied[] }  (uniform with MutEngine.mutate)
   */
  function generate(rng, userCfg) {
    const cfg = Object.assign({}, DEFAULTS, userCfg || {});
    const ops = [];
    let html = "";
    const P = patterns(cfg);
    if (P.length && bool(rng, 0.35)) {
      const p = pick(rng, P);
      html += p.html;
      ops.push(p.id);
    }
    html += genNode(rng, cfg, cfg.depth);
    ops.push("tree(d" + cfg.depth + ")");
    if (cfg.useMarkdown && bool(rng, 0.25)) {
      html = pick(rng, ["post **body**: ", "quote > ", "text [label](", "## head\n\n"])
           + html
           + pick(rng, [" [x](y)", " :)", "\n\n---", ")"]);
      ops.push("md-context");
    }
    if (bool(rng, 0.1)) {
      html = encodeString(rng, html, { entityProb: 1, noSemiProb: 0, invisProb: 0 });
      ops.push("full-entity");
    }
    return { html, opsApplied: ops };
  }

  return { generate, DEFAULTS, encodeString };
})();
if (typeof module !== "undefined") module.exports = Generator;

/* ============================================================================
 * mutation_engine.js — seeded, reproducible HTML5 mutation operators
 *
 * Every operator targets a specific clause of the HTML5 tree-construction
 * algorithm. mutate() composes 1..N operators over a corpus seed using a
 * mulberry32 PRNG — same seed + same ops => byte-identical candidate,
 * so every finding in the export is exactly reproducible.
 * ========================================================================== */
"use strict";
const MutEngine = (() => {
  function mulberry32(a) {
    return function () {
      a |= 0; a = (a + 0x6D2B79F5) | 0;
      let t = Math.imul(a ^ (a >>> 15), 1 | a);
      t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
      return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    };
  }
  const pick  = (rng, arr) => arr[Math.floor(rng() * arr.length)];
  const at    = (rng, s)    => Math.floor(rng() * (s.length + 1));
  const spliceIn = (s, pos, frag) => s.slice(0, pos) + frag + s.slice(pos);
  const wrap  = (s, rng, pre, post) => {
    const a = at(rng, s), b = Math.min(s.length, a + Math.floor(rng() * (s.length - a)));
    return s.slice(0, a) + pre + s.slice(a, b) + post + s.slice(b);
  };

  const OPS = {
    /* ---- adoption agency algorithm --------------------------------------- */
    injectFormatting: { family: "adoption", fn: (h, rng) =>
      spliceIn(h, at(rng, h), pick(rng, ["<b>","<i>","<em>","<font color=red>","<a href=#>",
                                         "</b>","</i>","</em>","</font>","</a>","<nobr>","</br>"])) },
    crossingTags:     { family: "adoption", fn: (h, rng) =>
      wrap(h, rng, "<b><i><em>", "</b></i>") },
    caseFlip:         { family: "adoption", fn: (h, rng) =>
      h.replace(/<\/?[a-z]+/, m => m.split("").map(c => rng() > .5 ? c.toUpperCase() : c).join("")) },

    /* ---- foster parenting (table insertion modes) ------------------------ */
    fosterBomb:       { family: "foster", fn: (h, rng) =>
      spliceIn(h, at(rng, h), pick(rng, ["<table>stray", "<table><td>", "</table><table>",
                                         "<table><tr><td>x</td></tr>", "<colgroup><table>"])) },
    tableWrap:        { family: "foster", fn: (h, rng) => wrap(h, rng, "<table><tr><td>", "</td></tr></table>") },

    /* ---- foreign content / namespace pivots ------------------------------ */
    nsPivot:          { family: "foreign", fn: (h, rng) =>
      spliceIn(h, at(rng, h), pick(rng, ["<svg><desc>", "<svg><foreignObject>", "<math><mtext>",
        "<math><mglyph>", "<math><malignmark>", "<math><annotation-xml encoding=\"text/html\">",
        "</svg>", "</math>", "<svg>", "<math>"])) },
    cdataPivot:       { family: "foreign", fn: (h, rng) =>
      spliceIn(h, at(rng, h), "<svg><![CDATA[]]>" + (rng() > .5 ? "" : "</svg>")) },

    /* ---- rawtext / RCDATA / escapable text ------------------------------- */
    rawtextWrap:      { family: "rawtext", fn: (h, rng) => {
      const t = pick(rng, ["style", "xmp", "textarea", "title", "iframe", "noembed", "noframes"]);
      const close = rng() > .4 ? "</" + t + ">" : "</" + t;   // sometimes drop the '>'
      return wrap(h, rng, "<" + t + ">", close); } },
    plaintextTail:    { family: "rawtext", fn: (h, rng) =>
      spliceIn(h, at(rng, h), "<plaintext>") },

    /* ---- comment & bogus-comment edge cases ------------------------------ */
    commentSplit:     { family: "comment", fn: (h, rng) =>
      spliceIn(h, at(rng, h), pick(rng, ["<!--", "-->", "--!>", "<!--->", "<!-->", "<?", "</ >",
                                         "<!---", "--->", "<!-- -- -->"])) },

    /* ---- encoding / tokenization ----------------------------------------- */
    entityTwist:      { family: "encoding", fn: (h, rng) =>
      h.replace(/(=)(["']?)([^"'\s>]{1,24})/, (m, eq, q, val) => {
        const twist = pick(rng, ["&NewLine;", "&Tab;", "&#x0;", "&#9;", "&#x0009;", "&colon;"]);
        const i2 = Math.floor(rng() * (val.length + 1));
        return eq + q + val.slice(0, i2) + twist + val.slice(i2);
      }) },
    nullByte:         { family: "encoding", fn: (h, rng) => spliceIn(h, at(rng, h), "\u0000") },
    dupAttr:          { family: "encoding", fn: (h, rng) =>
      h.replace(/<[a-z]+(\s+[a-z-]+(=("[^"]*")|[^\s>]+)?)/i,
                m => m + " " + pick(rng, ["src", "href", "onerror", "title"]) + "=dup") },

    /* ---- form pointer & select scope ------------------------------------- */
    formPointer:      { family: "form", fn: (h, rng) =>
      spliceIn(h, at(rng, h), pick(rng, ["<form id=fz>", "</form>", "<form>", " form=\"fz\""])) },
    selectScope:      { family: "select", fn: (h, rng) =>
      wrap(h, rng, "<select>", rng() > .5 ? "</select>" : "") },
    optgroupPivot:    { family: "select", fn: (h, rng) =>
      spliceIn(h, at(rng, h), pick(rng, ["<optgroup>", "<option>", "</select>", "<select><style>"])) },

    /* ---- template & nested browsing contexts ------------------------------ */
    templateWrap:     { family: "template", fn: (h, rng) =>
      wrap(h, rng, "<template>", rng() > .4 ? "</template>" : "") },
    srcdocNest:       { family: "template", fn: (h, rng) =>
      spliceIn(h, at(rng, h),
        "<iframe srcdoc=\"&lt;svg onload=top.postMessage({t:'mxss_exec',id:'srcdoc-nest'},'*')&gt;\"></iframe>") }
  };

  const FAMILIES = [...new Set(Object.values(OPS).map(o => o.family))];

  /**
   * mutate(html, rng, nOps, allowedFamilies) -> { html, opsApplied[] }
   */
  function mutate(html, rng, nOps, allowedFamilies) {
    const pool = Object.entries(OPS).filter(([n, o]) =>
      !allowedFamilies || allowedFamilies.includes(o.family));
    const applied = [];
    let out = html;
    for (let k = 0; k < nOps; k++) {
      const [name, op] = pick(rng, pool);
      try { out = op.fn(out, rng); applied.push(name); }
      catch (e) { applied.push(name + "!err"); }
    }
    return { html: out, opsApplied: applied };
  }

  return { mulberry32, mutate, OPS, FAMILIES };
})();
if (typeof module !== "undefined") module.exports = MutEngine;

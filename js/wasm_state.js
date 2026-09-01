/* ============================================================================
 * wasm_state.js — persistent verdict store for the HTML5 mutation fuzzer
 *
 *   Layer 0  WASM linear memory  (survives DOM wipes / blob exec in-frame)
 *   Layer 1  localStorage mirror (survives navigation)
 *   Layer 2  BroadcastChannel    (streams hits to collector.html, survives
 *                                 even destruction of the fuzzing frame)
 * Falls back to a JS Map if WASM instantiation fails.
 * Module built by tools/build_wasm.py — 1024 slots x 16 bytes:
 *   [ hash:u32 | hits:u32 | verdict_flags:u32 | reserved:u32 ]
 * ========================================================================== */
"use strict";
const MXSSState = (() => {
  const WASM_B64 = "AGFzbQEAAAABDgNgAAF/YAJ/fwF/YAAAAwQDAgEABQQBAQEQByMEBm1lbW9yeQIABXJlc2V0AAAGcmVjb3JkAAEFdG90YWwAAgqdAQMNAEEAQQBBgIAB/AsAC2IBA38CQANAIAJBgAhPDQEgAkEQbCEDIAMoAgAhBCAERSAEIABGcgRAIARFBEAgAyAANgIACyADIAMoAgRBAWo2AgQgAyADKAIIIAFyNgIIIAIPCyACQQFqIQIMAAsLQX8PCyoBAn8CQANAIABBgAhPDQEgASAAQRBsKAIEaiEBIABBAWohAAwACwsgAQs=";
  const SLOT_COUNT = 1024, LS_KEY = "mxss_state_v2", CHAN = "mxss_lab";

  const V = {                 // verdict bit field
    DIVERGE:  1,              // reparse serialization differs
    NEWSCRIPT:2,              // reparse GREW script-capable surface (mXSS prime)
    CANARY:   4,              // payload actually executed (postMessage canary)
    NSPIVOT:  8,              // namespace histogram shifted (svg/math)
    FOSTER:   16,             // table foster-parenting signature
    RAWTEXT:  32,             // rawtext/rcdata element involved in divergence
    ENCODE:   64,             // entity/null/charset mutation observed
    ERR:      128,            // script error observed during exec
    SANBYPASS:256,            // critical surface survives a sanitizer engine
    SMXSS:    512             // critical surface appears on REPARSE of sanitized output
  };

  let api = null, fallback = null, backend = "uninit";
  let bc = null, dirty = 0, flushTimer = null;
  const meta = new Map();     // hash -> {seed, ops, html, firstTs, lastTs}
  const listeners = [];

  const fnv1a = (str) => {
    let h = 0x811c9dc5 >>> 0;
    for (let k = 0; k < str.length; k++) {
      h ^= str.charCodeAt(k);
      h = Math.imul(h, 0x01000193) >>> 0;
    }
    return h >>> 0;
  };

  async function init() {
    try { bc = new BroadcastChannel(CHAN); } catch (e) { bc = null; }
    try {
      const bytes = Uint8Array.from(atob(WASM_B64), c => c.charCodeAt(0));
      const { instance } = await WebAssembly.instantiate(bytes, {});
      api = instance.exports;
      api.reset();
      backend = "wasm";
    } catch (e) {
      fallback = new Map();
      backend = "js-fallback";
    }
    // restore Layer-1 mirror
    try {
      const saved = JSON.parse(localStorage.getItem(LS_KEY) || "[]");
      for (const rec of saved) bump(rec[0], rec[2], rec[1]);
    } catch (e) { /* corrupted mirror — start clean */ }
    return backend;
  }

  function bump(hash, flags, times) {
    for (let t = 0; t < times; t++) {
      if (api) api.record(hash, flags);
      else {
        const cur = fallback.get(hash) || [0, 0];
        fallback.set(hash, [cur[0] + 1, cur[1] | flags]);
      }
    }
  }

  function record(idStr, verdictBits, info) {
    const hash = fnv1a(idStr);
    bump(hash, verdictBits, 1);
    if (info) {
      const m = meta.get(hash) || { seed: info.seed, ops: info.ops, html: info.html,
                                    firstTs: Date.now(), lastTs: 0 };
      m.lastTs = Date.now();
      if (info.note) m.note = info.note;
      meta.set(hash, m);
    }
    dirty++;
    const msg = { t: "hit", hash, bits: verdictBits, ts: Date.now() };
    if (bc) { try { bc.postMessage(msg); } catch (e) {} }
    listeners.forEach(fn => { try { fn(msg); } catch (e) {} });
    if (dirty >= 25 && !flushTimer) flushTimer = setTimeout(flush, 400);
    return hash;
  }

  function snapshot() {
    const out = [];
    if (api) {
      const m = new Uint32Array(api.memory.buffer);
      for (let s = 0; s < SLOT_COUNT; s++) {
        const h = m[s * 4];
        if (h !== 0) out.push({ hash: h, hits: m[s * 4 + 1], flags: m[s * 4 + 2] });
      }
    } else if (fallback) {
      for (const [h, v] of fallback) out.push({ hash: h, hits: v[0], flags: v[1] });
    }
    return out;
  }

  function flush() {
    flushTimer = null; dirty = 0;
    try {
      const slim = snapshot().map(r => [r.hash, r.hits, r.flags]);
      localStorage.setItem(LS_KEY, JSON.stringify(slim));
    } catch (e) {}
  }

  function total() { return api ? api.total() : snapshot().reduce((a, r) => a + r.hits, 0); }

  function reset() {
    if (api) api.reset(); else fallback = new Map();
    meta.clear();
    try { localStorage.removeItem(LS_KEY); } catch (e) {}
    if (bc) { try { bc.postMessage({ t: "reset" }); } catch (e) {} }
  }

  function exportJSON() {
    flush();
    return JSON.stringify({
      tool: "html5-mutation-fuzzer", version: "2.0", backend,
      exported: new Date().toISOString(),
      verdictBits: V,
      records: snapshot().map(r => Object.assign({}, r, meta.get(r.hash) || {}))
    }, null, 2);
  }

  return { init, record, snapshot, total, reset, flush, exportJSON, fnv1a,
           onEvent: fn => listeners.push(fn),
           get backend() { return backend; }, V };
})();
if (typeof module !== "undefined") module.exports = MXSSState;

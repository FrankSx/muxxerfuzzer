/* ============================================================================
 * storage_idb.js — IndexedDB long-term hit store (v3.0 lineage, v4.0 fixes)
 *
 * Layer 3 of the persistence stack (WASM mem -> localStorage -> BC channel
 * -> IndexedDB). Compressed metadata-only records; full engine outputs are
 * recomputed on replay. Fixes vs v3.0:
 *   - actually persists the latest session id (v3.0 read a key never written)
 *   - dedup by candidate hash (v3.0 stored repeat hits repeatedly)
 *   - quota/transaction errors logged, not swallowed
 * ========================================================================== */
"use strict";
const IDBStore = (() => {
  const DB_NAME = "MXSSv4", DB_VERSION = 1, STORE = "hits";
  const SESSION = "fz_" + Date.now().toString(36) + "_" +
                  Math.floor(Math.random() * 1e6).toString(36);
  let db = null, ready = false;
  const seen = new Set();   // dedup hashes this session

  function init() {
    return new Promise(resolve => {
      let req;
      try { req = indexedDB.open(DB_NAME, DB_VERSION); }
      catch (e) { console.warn("IDBStore unavailable:", e.message); return resolve(false); }
      req.onerror = () => { console.warn("IDBStore open failed:", req.error); resolve(false); };
      req.onsuccess = () => {
        db = req.result; ready = true;
        try { localStorage.setItem("mxss_latest_session", SESSION); } catch (e) {}
        resolve(true);
      };
      req.onupgradeneeded = e => {
        const d = e.target.result;
        if (!d.objectStoreNames.contains(STORE)) {
          const st = d.createObjectStore(STORE, { keyPath: "id", autoIncrement: true });
          st.createIndex("session", "session", { unique: false });
          st.createIndex("hash", "hash", { unique: false });
        }
      };
    });
  }

  function tx(mode) { return db.transaction([STORE], mode).objectStore(STORE); }

  /** save(hit) — hit: {hash, seedId, ops, html, bits, matrixSummary, note, canaryIds} */
  function save(hit) {
    if (!ready || seen.has(hit.hash)) return Promise.resolve(false);
    seen.add(hit.hash);
    return new Promise(resolve => {
      try {
        const rec = Object.assign({ session: SESSION, ts: new Date().toISOString() }, hit);
        const rq = tx("readwrite").add(rec);
        rq.onsuccess = () => resolve(true);
        rq.onerror = () => { console.warn("IDBStore add failed:", rq.error); resolve(false); };
      } catch (e) { console.warn("IDBStore tx failed:", e.message); resolve(false); }
    });
  }

  function getAll(indexName, key) {
    if (!ready) return Promise.resolve([]);
    return new Promise(resolve => {
      try {
        const src = indexName ? tx("readonly").index(indexName) : tx("readonly");
        const rq = key !== undefined ? src.getAll(key) : src.getAll();
        rq.onsuccess = () => resolve(rq.result || []);
        rq.onerror = () => resolve([]);
      } catch (e) { resolve([]); }
    });
  }

  function clear() {
    if (!ready) return Promise.resolve();
    seen.clear();
    return new Promise(resolve => {
      const t = db.transaction([STORE], "readwrite");
      t.objectStore(STORE).clear();
      t.oncomplete = () => resolve();
      t.onerror = () => resolve();
    });
  }

  async function stats() {
    const mine = await getAll("session", SESSION);
    const size = mine.reduce((a, h) => a + JSON.stringify(h).length, 0);
    return { count: mine.length, bytes: size, session: SESSION };
  }

  return { init, save, getAll, clear, stats,
           get session() { return SESSION; },
           get ready() { return ready; } };
})();
if (typeof module !== "undefined") module.exports = IDBStore;

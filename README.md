# mXSS Fuzzer v4.1 — BOUNTY HUNTER

Fusion build, round two: **v2.0 engine core** (WASM-persistent verdicts,
3-path differential oracle, sandbox exec canaries, seeded determinism)
+ **v3.0 arsenal** (sanitizer matrix, IndexedDB, generational engine)
+ **v4.1 weapons** (ddmin minimal-PoC shrinker, dp-WARN evolver,
11-engine bug-bounty matrix) — merged from two parallel builds.
Third-party libs load from version-pinned CDN URLs at page load
(see VENDOR.md); everything first-party is local, zero build step.

## The matrix (11 engines)

| engine | kind | disclosure channel |
|---|---|---|
| none / regex / text | controls | hand-rolled filter stand-ins (app-scope bugs) |
| DOMPurify 3.2.5 ×3 configs | library | Cure53 GHSA — rich CVE history |
| js-xss 1.0.15 | library | leizongmin GHSA / npm `xss` |
| Angular $sanitize 1.8.3 | library | Google angular.js GHSA — legacy but everywhere |
| **Native Sanitizer API** | browser | **Chromium VRP / Mozilla — highest payout class** |
| jQuery .html() | sink | jquery GHSA / app scope — *executes* scripts on insert |
| Markdown→DOMPurify | sink | marked GHSA / app scope — comment fields, GitLab-style |

`programs()` in the export maps every engine to its disclosure channel
and payout class. sanitize-html is deliberately absent: no browser
bundle exists (Node-only server terrain — roadmap).

## The weapons

- **ddmin** (Zeller delta debugging, tag-aware first pass): shrink any
  triggering payload to its minimal PoC. Validated: 81 chars → 8
  (`<script>`) in 59 oracle calls. Oracles: per-engine verdict
  (`Sanitizer.oracleFor`) or **exec-canary** (`ddmin[canary]` button)
  which minimizes while the payload still fires in the sandbox.
- **evolve** — the dp-WARN hunter: hammer WARN residue with the
  EVOLVE_OPS flip set (mglyph injects, `<!-- --!>`, tab-split
  `java\tscript:`, unclosed-script regex-blindness, annotation-xml)
  until the verdict flips to BYPASS/mXSS. Simulated-annealing drift.
  Validated: cold seed `<b>safe</b>` → flip in 2 rounds.
- **evolve-every-WARN campaign** — batch mode: evolve every WARN
  surface in the hit list, log all flips.
- `MinimizerX.shrink/climb/hunt` — score-based wrappers for scripts.

## Verdict bits (10)

DIVERGE 1 · NEWSCRIPT 2 · CANARY 4 · NSPIVOT 8 · FOSTER 16 ·
RAWTEXT 32 · ENCODE 64 · ERR 128 · SANBYPASS 256 · SMXSS 512

## Persistence (4 layers)

WASM linear memory (233-byte hand-built module) → localStorage →
BroadcastChannel collector.html → IndexedDB (dedup'd, session-indexed).

## Usage

```bash
python3 tools/runner.py serve          # http://127.0.0.1:8137/harness.html
python3 tools/runner.py headless --rounds 300 --seed 1337 --exec
python3 tools/runner.py report mxss_v4_*.json -o post.md
```

Headless: `harness.html?auto=N&seed=S&exec=1&san=1&mode=mixed`
Weapon self-check: `harness.html?auto=1&ddtest=1` (ddmin + evolve
smoke test — note `auto=1` is required, ddtest nests under auto mode).

## Gotchas learned the hard way

- **jQuery sink executes candidates in-page** — the harness pins
  `window.alert/confirm/prompt` to no-ops so legacy payloads can't
  freeze the UI. Exec verdicts still require the sandboxed canary.
- IndexedDB hangs forever on `file://` in some builds — init is raced
  with a 1.5 s timeout; everything else works regardless.
- `Minimizer.ddmin`/`evolve` (oracle API) is canonical;
  `MinimizerX.*` wraps it for score-driven batch use.

— frankSx × K3, dual-build merge. Hunt well. ⌬

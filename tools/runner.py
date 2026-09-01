#!/usr/bin/env python3
"""tools/runner.py — mXSS Fuzzer v4.1 command runner

Usage:
  python3 tools/runner.py serve                          # http://127.0.0.1:8137/harness.html
  python3 tools/runner.py headless --rounds 300 --seed 1337 --exec
  python3 tools/runner.py report mxss_v4_*.json -o post.md

headless requires:  pip install playwright && playwright install chromium
"""
import argparse, glob, http.server, json, os, socketserver, sys, time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PORT = 8137


def serve():
    os.chdir(ROOT)
    with socketserver.TCPServer(("127.0.0.1", PORT),
                                http.server.SimpleHTTPRequestHandler) as httpd:
        print(f"serving {ROOT}")
        print(f"  harness   -> http://127.0.0.1:{PORT}/harness.html")
        print(f"  collector -> http://127.0.0.1:{PORT}/collector.html")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            pass


def headless(rounds, seed, exec_, mode, san, ddtest):
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        sys.exit("headless needs playwright:\n"
                 "  pip install playwright && playwright install chromium")
    q = f"auto={rounds}&seed={seed}&mode={mode}&san={1 if san else 0}"
    if exec_:
        q += "&exec=1"
    if ddtest:
        q += "&ddtest=1"
    url = f"http://127.0.0.1:{PORT}/harness.html?{q}"

    import threading
    threading.Thread(target=serve, daemon=True).start()
    time.sleep(1.0)

    with sync_playwright() as p:
        browser = p.chromium.launch()
        page = browser.new_page()
        page.goto(url)
        page.wait_for_function("document.title === 'MXSS_DONE'",
                               timeout=max(120_000, rounds * 500))
        summary = page.inner_text("#summary")
        browser.close()
    out = os.path.join(ROOT, f"mxss_v4_{int(time.time())}.json")
    with open(out, "w") as fh:
        fh.write(summary)
    print(f"saved {out}")
    print(summary[:2000])


def report(pattern, out_path):
    files = sorted(glob.glob(pattern))
    if not files:
        sys.exit(f"no files match {pattern!r}")
    data = json.load(open(files[-1]))
    bits = data.get("verdictBits", {})
    programs = {p["id"]: p for p in data.get("programs", [])}
    hits = data.get("hits", [])

    def score(h):
        b = h.get("bits", 0)
        return ((b & bits.get("CANARY", 4)) != 0) * 4 \
             + ((b & bits.get("SMXSS", 512)) != 0) * 2 \
             + ((b & bits.get("SANBYPASS", 256)) != 0)

    hits.sort(key=score, reverse=True)
    L = []
    L.append(f"# mXSS Fuzzer run — {data.get('exported', '?')}")
    L.append("")
    L.append(f"- backend: `{data.get('backend')}`  session: `{data.get('session')}`")
    st = data.get("stats", {})
    L.append(f"- iterations: {st.get('iter')}  kept: {st.get('kept')}  "
             f"canary: {st.get('canary')}  sanitizer-bypass: {st.get('san')}  "
             f"s-mXSS: {st.get('smxss')}")
    L.append("")
    L.append("| # | seed | ops | verdict bits | matrix | disclosure channel |")
    L.append("|---|---|---|---|---|---|")
    for i, h in enumerate(hits, 1):
        chan = ""
        for eid in (h.get("matrixSummary") or "").split():
            eid = eid.split(":")[0]
            if eid in programs:
                chan = programs[eid]["channel"]
                break
        L.append(f"| {i} | {h.get('seedId')} | {h.get('ops','')} | {h.get('bits')} "
                 f"| `{h.get('matrixSummary','')}` | {chan} |")
    mini = data.get("minimized") or {}
    if mini:
        L.append("")
        L.append("## Minimal PoCs (ddmin)")
        L.append("")
        for h, runs in mini.items():
            for r in runs:
                L.append(f"- hash `{h}` engine `{r['engine']}`: "
                         f"{r['origLen']} -> {len(r['minHtml'])} chars "
                         f"({r['steps']} oracle calls)")
                L.append(f"  ```html\n  {r['minHtml']}\n  ```")
    md = "\n".join(L) + "\n"
    if out_path:
        with open(out_path, "w") as fh:
            fh.write(md)
        print(f"wrote {out_path}")
    else:
        print(md)


if __name__ == "__main__":
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve")
    hp = sub.add_parser("headless")
    hp.add_argument("--rounds", type=int, default=100)
    hp.add_argument("--seed", type=int, default=1)
    hp.add_argument("--exec", action="store_true")
    hp.add_argument("--mode", default="mixed")
    hp.add_argument("--no-san", dest="san", action="store_false")
    hp.add_argument("--ddtest", action="store_true")
    rp = sub.add_parser("report")
    rp.add_argument("pattern")
    rp.add_argument("-o", dest="out", default=None)
    a = ap.parse_args()
    if a.cmd == "serve":
        serve()
    elif a.cmd == "headless":
        headless(a.rounds, a.seed, a.exec, a.mode, a.san, a.ddtest)
    else:
        report(a.pattern, a.out)

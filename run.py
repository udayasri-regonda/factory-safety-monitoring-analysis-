#!/usr/bin/env python3
"""Factory Safety Monitoring & Analysis - command line entry point."""
import argparse, os, sys, functools, http.server, socketserver
sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))
from fss import config as C, pipeline as P


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("command", choices=["all", "generate", "detect", "evaluate", "reproduce", "analyze", "demo", "export", "serve"])
    ap.add_argument("--profile", choices=list(C.PROFILES), default="full")
    ap.add_argument("--seed", type=int, default=C.DEFAULT_SEED)
    ap.add_argument("--out", default=None, help="output directory (default: output/<profile>)")
    ap.add_argument("--port", type=int, default=8080)
    ap.add_argument("--host", default="127.0.0.1", help="serve: bind address (default localhost only)")
    ap.add_argument("--events", default=None, help="analyze/serve: alarm-event CSV to ingest (default: data/csv/alarm_events.csv)")
    ap.add_argument("--mapping", default=None, help="analyze/serve: JSON field mapping (default: identity mapping)")
    ap.add_argument("--finding", default=None, help="export: finding id, e.g. F-UNSF-1A2B3C4D")
    a = ap.parse_args()
    out = a.out or os.path.join("output", a.profile)
    prof = C.PROFILES[a.profile]
    if a.command == "all":
        P.run_all(out, a.profile, a.seed)
    elif a.command == "generate":
        print(P.step_generate(out, prof, a.seed)["row_counts"])
    elif a.command == "detect":
        _, an, _ = P.step_detect(out); print(len(an), "findings")
    elif a.command == "evaluate":
        _, an, _ = P.step_detect(out); print(P.step_evaluate(out, an)["overall"])
    elif a.command == "reproduce":
        print(P.step_reproduce(out, prof, a.seed)["run1_equals_run2"])
    elif a.command == "analyze":
        from fss import analysis
        r = analysis.run_analysis(out, a.events, a.mapping)
        ing = r["summary"]["ingest"]
        print(f"run {r['run_id']}: read {ing['rows_read']}, valid {ing['rows_valid']}, rejected {ing['rows_rejected']} {ing['rejects_by_reason']}")
        print(f"findings: {len(r['findings'])} {r['summary']['findings_by_rule']}\ndigest: {r['digest']}")
    elif a.command == "demo":
        from fss import analysis, demo
        if not os.path.exists(os.path.join(out, "data", "csv", "alarm_events.csv")):
            P.step_generate(out, prof, a.seed)
        feed, n, nbad = demo.make_feed(out)
        print(f"demo feed written: {feed} ({n} good rows + {nbad} deliberately defective rows)")
        r = analysis.run_analysis(out, feed, os.path.join("mappings", "example_historian_export.json"))
        ing = r["summary"]["ingest"]
        print(f"ingest: read {ing['rows_read']}, valid {ing['rows_valid']}, rejected {ing['rows_rejected']} {ing['rejects_by_reason']}")
        top = next((f for f in r["findings"] if f["severity"] in ("CRITICAL", "HIGH")), None)
        print(f"findings: {len(r['findings'])}; digest {r['digest'][:16]}\nsuggested investigation: " + (f"{top['finding_id']} - {top['title']}" if top else "none"))
        print("next: python run.py serve --profile %s --events %s --mapping mappings/example_historian_export.json" % (a.profile, feed))
    elif a.command == "export":
        from fss import analysis, export, store
        if not a.finding:
            ap.error("export needs --finding")
        con = store.connect(analysis.db_path(out))
        b = export.build_bundle(con, a.finding)
        if b is None:
            sys.exit(f"unknown finding {a.finding}; run 'analyze' first")
        dest = os.path.join(out, "exports", f"{a.finding}_investigation.zip")
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        open(dest, "wb").write(b[0])
        print("exported", dest)
    elif a.command == "serve":
        from fss import server
        server.serve(out, a.host, a.port, a.events, a.mapping)

if __name__ == "__main__":
    main()

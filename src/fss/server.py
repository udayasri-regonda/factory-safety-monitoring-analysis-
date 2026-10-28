"""Local HTTP server: JSON API + single-page dashboard. Standard library only. Binds to 127.0.0.1 by default.

SECURITY NOTE: this is a local prototype. There is no authentication; the 'actor' names typed into the dashboard are
self-declared and only recorded in the audit log. Do not expose the port to a network without adding authentication.
"""
from __future__ import annotations

import functools
import json
import mimetypes
import os
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

from . import analysis, api, export, store, workflow as W

WEB = os.path.join(os.path.dirname(os.path.abspath(__file__)), "web")


class App:
    def __init__(self, out, events_csv=None, mapping_path=None):
        self.out, self.events_csv, self.mapping_path = out, events_csv, mapping_path
        self.db = analysis.db_path(out)
        self.lock = threading.Lock()           # serialise re-analysis

    def con(self):
        return store.connect(self.db)


def make_handler(app):
    class H(BaseHTTPRequestHandler):
        server_version = "FSS/1.0"

        def log_message(self, *a):
            pass

        def _send(self, code, body, ctype="application/json", extra=None):
            if not isinstance(body, (bytes, bytearray)):
                body = json.dumps(body, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(body)))
            for k, v in (extra or {}).items():
                self.send_header(k, v)
            self.end_headers()
            self.wfile.write(body)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            if not n:
                return {}
            try:
                return json.loads(self.rfile.read(n) or b"{}")
            except ValueError:
                raise W.WorkflowError("request body is not valid JSON")

        def _route(self, method):
            u = urlparse(self.path)
            q = {k: v[0] for k, v in parse_qs(u.query).items() if v and v[0] != ""}
            p = u.path
            if method == "GET" and p in ("/", "/index.html"):
                with open(os.path.join(WEB, "index.html"), "rb") as fh:
                    return self._send(200, fh.read(), "text/html; charset=utf-8")
            if method == "GET" and p.startswith("/reports/"):
                f = os.path.normpath(os.path.join(app.out, "reports", p[len("/reports/"):]))
                if not f.startswith(os.path.normpath(os.path.join(app.out, "reports"))) or not os.path.isfile(f):
                    return self._send(404, {"error": "not found"})
                with open(f, "rb") as fh:
                    return self._send(200, fh.read(), mimetypes.guess_type(f)[0] or "application/octet-stream")
            con = app.con()
            try:
                if method == "GET":
                    if p == "/api/overview":
                        return self._send(200, api.overview(con, q.get("plant")))
                    if p == "/api/run":
                        return self._send(200, api.run_info(con))
                    if p == "/api/findings":
                        flt = {k: q.get(k) for k in ("plant", "machine", "severity", "rule", "review", "date_from", "date_to", "q")}
                        return self._send(200, api.findings_list(con, limit=int(q.get("limit", 500)), offset=int(q.get("offset", 0)), **flt))
                    m = re.fullmatch(r"/api/findings/([A-Z0-9-]+)(/export)?", p)
                    if m:
                        if m.group(2):
                            b = export.build_bundle(con, m.group(1))
                            if b is None:
                                return self._send(404, {"error": "unknown finding"})
                            return self._send(200, b[0], "application/zip", {"Content-Disposition": f'attachment; filename="{m.group(1)}_investigation.zip"'})
                        d = api.finding_detail(con, m.group(1))
                        return self._send(200, d) if d else self._send(404, {"error": f"unknown finding {m.group(1)}"})
                    if p == "/api/machines":
                        return self._send(200, api.machines(con, q.get("plant"), q.get("severity"), q.get("date_from"), q.get("date_to"), q.get("sort", "risk"), q.get("machine")))
                    m = re.fullmatch(r"/api/machines/(M\d+)", p)
                    if m:
                        d = api.machine_detail(con, m.group(1))
                        return self._send(200, d) if d else self._send(404, {"error": "unknown machine"})
                    if p == "/api/actions":
                        return self._send(200, api.actions(con))
                    if p == "/api/events":
                        return self._send(200, api.events(con, q.get("machine"), q.get("date_from"), q.get("date_to"), int(q.get("limit", 200))))
                    if p == "/api/quality":
                        return self._send(200, api.quality(con))
                    if p == "/api/evaluation":
                        return self._send(200, api.evaluation(con))
                    if p == "/api/plants":
                        return self._send(200, api.plants(con))
                    if p == "/api/rules":
                        return self._send(200, api.rules())
                if method == "POST":
                    b = self._body()
                    m = re.fullmatch(r"/api/findings/([A-Z0-9-]+)/review", p)
                    if m:
                        W.set_review(con, m.group(1), b.get("status"), b.get("reviewer"), b.get("note", ""))
                        return self._send(200, api.finding_detail(con, m.group(1)))
                    m = re.fullmatch(r"/api/findings/([A-Z0-9-]+)/actions", p)
                    if m:
                        aid = W.create_action(con, m.group(1), b.get("description"), b.get("owner"), b.get("due_date"), b.get("actor"))
                        return self._send(201, dict(wb_action_id=aid, finding=api.finding_detail(con, m.group(1))))
                    m = re.fullmatch(r"/api/actions/(WA-\d+)/status", p)
                    if m:
                        W.set_action_status(con, m.group(1), b.get("status"), b.get("actor"))
                        fid = con.execute("SELECT finding_id FROM wb_actions WHERE wb_action_id=?", (m.group(1),)).fetchone()[0]
                        return self._send(200, api.finding_detail(con, fid))
                    m = re.fullmatch(r"/api/actions/(WA-\d+)/verify", p)
                    if m:
                        W.add_verification(con, m.group(1), b.get("verified_by"), b.get("method"), b.get("evidence_text"), b.get("evidence_ref", ""))
                        fid = con.execute("SELECT finding_id FROM wb_actions WHERE wb_action_id=?", (m.group(1),)).fetchone()[0]
                        return self._send(200, api.finding_detail(con, fid))
                    if p == "/api/rerun":
                        prev = api._last_run(con)
                        con.close()
                        with app.lock:
                            r = analysis.run_analysis(app.out, app.events_csv, app.mapping_path)
                        return self._send(200, dict(run_id=r["run_id"], digest=r["digest"], previous_digest=prev["digest"] if prev else None,
                                                    identical_to_previous=bool(prev and prev["digest"] == r["digest"]), findings=len(r["findings"]), events=r["n_events"]))
                return self._send(404, {"error": f"no route {method} {p}"})
            except W.WorkflowError as e:
                return self._send(400, {"error": str(e)})
            except Exception as e:      # surface a meaningful message instead of a blank page
                return self._send(500, {"error": f"{type(e).__name__}: {e}"})
            finally:
                try:
                    con.close()
                except Exception:
                    pass

        def do_GET(self):
            self._route("GET")

        def do_POST(self):
            self._route("POST")
    return H


def make_server(app, host="127.0.0.1", port=8080):
    return ThreadingHTTPServer((host, port), make_handler(app))


def serve(out, host="127.0.0.1", port=8080, events_csv=None, mapping_path=None):
    app = App(out, events_csv, mapping_path)
    if not os.path.exists(app.db):
        analysis.run_analysis(out, events_csv, mapping_path)
    srv = make_server(app, host, port)
    print(f"Dashboard: http://{host}:{port}   (Ctrl+C to stop)")
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("stopped")

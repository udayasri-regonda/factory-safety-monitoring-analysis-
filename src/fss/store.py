"""Investigation workbench storage (SQLite, stdlib).

Derived tables (events, findings, evidence, risk, rejects) are rebuilt on every analysis run.
Human-entered tables (review, wb_actions, wb_verifications, audit_log) are NEVER touched by a re-run, so
investigator work survives re-analysis. audit_log is append-only (triggers).
"""
from __future__ import annotations

import json
import sqlite3
from datetime import datetime, timezone

DDL = """
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS analysis_runs(run_id INTEGER PRIMARY KEY AUTOINCREMENT, run_ts TEXT NOT NULL, source TEXT, digest TEXT NOT NULL,
  n_events INTEGER, n_rejects INTEGER, n_findings INTEGER, summary_json TEXT);
CREATE TABLE IF NOT EXISTS machines(machine_id TEXT PRIMARY KEY, plant_id TEXT, machine_name TEXT, machine_type TEXT, criticality TEXT);
CREATE TABLE IF NOT EXISTS plants(plant_id TEXT PRIMARY KEY, plant_name TEXT);
CREATE TABLE IF NOT EXISTS alarm_defs(alarm_def_id TEXT PRIMARY KEY, alarm_code TEXT, severity TEXT, ack_sla_seconds INTEGER);
CREATE TABLE IF NOT EXISTS events(alarm_event_id TEXT PRIMARY KEY, machine_id TEXT, alarm_def_id TEXT, event_ts TEXT, clear_ts TEXT,
  machine_state TEXT, interlock_state TEXT, classification TEXT, flags TEXT, ack_id TEXT, ack_ts TEXT, ack_delay_s INTEGER);
CREATE INDEX IF NOT EXISTS ix_ev_m ON events(machine_id, event_ts);
CREATE TABLE IF NOT EXISTS incidents(incident_id TEXT PRIMARY KEY, machine_id TEXT, trigger_alarm_event_id TEXT, severity TEXT, opened_ts TEXT, status TEXT, incident_type TEXT);
CREATE TABLE IF NOT EXISTS source_actions(action_id TEXT PRIMARY KEY, incident_id TEXT, machine_id TEXT, action_type TEXT, assigned_to TEXT,
  verification_required INTEGER, status TEXT, opened_ts TEXT, verified_ts TEXT, verified_by TEXT, closed_ts TEXT, unverified_closure INTEGER);
CREATE TABLE IF NOT EXISTS ingest_rejects(source_line INTEGER, alarm_event_id TEXT, reasons TEXT, detail TEXT, machine_id TEXT, raw_event_ts TEXT);
CREATE TABLE IF NOT EXISTS findings(finding_id TEXT PRIMARY KEY, rule_id TEXT, rule_name TEXT, category TEXT, plant_id TEXT, machine_id TEXT, title TEXT,
  severity TEXT, window_start TEXT, window_end TEXT, detail_json TEXT, active INTEGER DEFAULT 1, first_run INTEGER, last_run INTEGER);
CREATE INDEX IF NOT EXISTS ix_f_m ON findings(machine_id);
CREATE TABLE IF NOT EXISTS finding_evidence(finding_id TEXT, seq INTEGER, record_type TEXT, record_id TEXT, ts TEXT, role TEXT, summary TEXT,
  PRIMARY KEY(finding_id, seq));
CREATE TABLE IF NOT EXISTS machine_risk(machine_id TEXT PRIMARY KEY, plant_id TEXT, rank INTEGER, risk_score REAL, breakdown_json TEXT, row_json TEXT);
CREATE TABLE IF NOT EXISTS review(finding_id TEXT PRIMARY KEY, review_status TEXT NOT NULL DEFAULT 'NEW'
  CHECK(review_status IN ('NEW','UNDER_REVIEW','CONFIRMED','DISMISSED')), reviewer TEXT, note TEXT, reviewed_ts TEXT);
CREATE TABLE IF NOT EXISTS wb_actions(wb_action_id TEXT PRIMARY KEY, finding_id TEXT NOT NULL, description TEXT NOT NULL, owner TEXT NOT NULL,
  due_date TEXT, status TEXT NOT NULL CHECK(status IN ('OPEN','IN_PROGRESS','COMPLETED','CLOSED')), created_ts TEXT, closed_ts TEXT, closed_by TEXT);
CREATE TABLE IF NOT EXISTS wb_verifications(verification_id TEXT PRIMARY KEY, wb_action_id TEXT NOT NULL REFERENCES wb_actions(wb_action_id),
  verified_by TEXT NOT NULL, method TEXT NOT NULL, evidence_text TEXT NOT NULL, evidence_ref TEXT, verified_ts TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS audit_log(audit_id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, actor TEXT, action TEXT NOT NULL, subject TEXT, detail TEXT);
CREATE TRIGGER IF NOT EXISTS audit_no_update BEFORE UPDATE ON audit_log BEGIN SELECT RAISE(ABORT,'audit_log is append-only'); END;
CREATE TRIGGER IF NOT EXISTS audit_no_delete BEFORE DELETE ON audit_log BEGIN SELECT RAISE(ABORT,'audit_log is append-only'); END;
"""
DERIVED = ["machines", "plants", "alarm_defs", "events", "incidents", "source_actions", "ingest_rejects", "finding_evidence", "machine_risk"]


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def connect(path):
    con = sqlite3.connect(path, timeout=30)
    con.row_factory = sqlite3.Row
    con.executescript(DDL)
    return con


def audit(con, actor, action, subject, detail=""):
    con.execute("INSERT INTO audit_log(ts,actor,action,subject,detail) VALUES(?,?,?,?,?)", (now(), actor, action, subject, detail))


def save_analysis(con, a):
    """Persist an analysis result (see analysis.run_analysis). Idempotent: findings are upserted by stable ID."""
    cur = con.execute("INSERT INTO analysis_runs(run_ts,source,digest,n_events,n_rejects,n_findings,summary_json) VALUES(?,?,?,?,?,?,?)",
                      (now(), a["source"], a["digest"], a["n_events"], len(a["rejects"]), len(a["findings"]), json.dumps(a["summary"])))
    run = cur.lastrowid
    for t in DERIVED:
        con.execute(f"DELETE FROM {t}")
    T = a["T"]
    con.executemany("INSERT INTO plants VALUES(?,?)", [(p["plant_id"], p["plant_name"]) for p in T["plants"]])
    con.executemany("INSERT INTO machines VALUES(?,?,?,?,?)", [(m["machine_id"], m["plant_id"], m["machine_name"], m["machine_type"], m["criticality"]) for m in T["machines"]])
    con.executemany("INSERT INTO alarm_defs VALUES(?,?,?,?)", [(d["alarm_def_id"], d["alarm_code"], d["severity"], d["ack_sla_seconds"]) for d in T["alarm_definitions"]])
    con.executemany("INSERT INTO events VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", a["event_rows"])
    con.executemany("INSERT INTO incidents VALUES(?,?,?,?,?,?,?)", [(i["incident_id"], i["machine_id"], i["trigger_alarm_event_id"], i["severity"], i["opened_ts"], i["status"], i["incident_type"]) for i in T["incidents"]])
    con.executemany("INSERT INTO source_actions VALUES(?,?,?,?,?,?,?,?,?,?,?,?)", a["source_action_rows"])
    con.executemany("INSERT INTO ingest_rejects VALUES(?,?,?,?,?,?)", [(r["source_line"], r["alarm_event_id"], r["reasons"], r["detail"], r["machine_id"], r["raw_event_ts"]) for r in a["rejects"]])
    for r in a["machine_risk"]:
        con.execute("INSERT INTO machine_risk VALUES(?,?,?,?,?,?)", (r["machine_id"], r["plant_id"], r["rank"], r["risk_score"], json.dumps(a["breakdowns"][r["machine_id"]]), json.dumps(r)))
    con.execute("UPDATE findings SET active=0")
    for f in a["findings"]:
        detail = {k: v for k, v in f.items() if k != "evidence"}
        con.execute("""INSERT INTO findings(finding_id,rule_id,rule_name,category,plant_id,machine_id,title,severity,window_start,window_end,detail_json,active,first_run,last_run)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?,1,?,?)
                       ON CONFLICT(finding_id) DO UPDATE SET rule_name=excluded.rule_name,title=excluded.title,severity=excluded.severity,window_start=excluded.window_start,
                       window_end=excluded.window_end,detail_json=excluded.detail_json,active=1,last_run=excluded.last_run""",
                    (f["finding_id"], f["rule_id"], f["rule_name"], f["category"], f["plant_id"], f["machine_id"], f["title"], f["severity"], f["window_start"], f["window_end"],
                     json.dumps(detail), run, run))
        con.execute("INSERT OR IGNORE INTO review(finding_id) VALUES(?)", (f["finding_id"],))
        con.executemany("INSERT INTO finding_evidence VALUES(?,?,?,?,?,?,?)",
                        [(f["finding_id"], n, e["record_type"], e["record_id"], e["ts"], e["role"], e["summary"]) for n, e in enumerate(f["evidence"])])
    audit(con, "system", "ANALYSIS_RUN", f"run {run}", f"digest={a['digest']} findings={len(a['findings'])} events={a['n_events']} rejects={len(a['rejects'])}")
    con.commit()
    return run

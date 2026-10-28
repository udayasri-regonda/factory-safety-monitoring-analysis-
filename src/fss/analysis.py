"""Analysis orchestration: ingest -> validate -> detect -> evaluate -> findings -> store.

Components are separate modules: ingest.py (adapter + record validation), detector.py (rules), findings.py (evidence & severity),
metrics.py (risk / KPIs / evaluation), store.py (SQLite). This module only wires them together.
"""
from __future__ import annotations

import hashlib
import json
import os

from . import exporters as X
from . import store
from .detector import detect_anomalies, classify_operations
from .findings import build_findings, machine_risk_breakdown
from .ingest import ingest_events, load_mapping, NATIVE_MAPPING
from .metrics import compute_metrics, evaluate

DB_NAME = "workbench.sqlite"


def db_path(out):
    return os.path.join(out, "db", DB_NAME)


def run_analysis(out, events_csv=None, mapping_path=None, store_result=True):
    """Run the full chain on `out` (a dataset directory). Reference tables come from out/data/csv; alarm events come from
    `events_csv` through the mapping (default: the native alarm_events.csv with the identity mapping)."""
    T = X.load_dataset(out)
    mapping = load_mapping(mapping_path) if mapping_path else NATIVE_MAPPING
    events_csv = events_csv or os.path.join(out, "data", "csv", "alarm_events.csv")
    ing = ingest_events(events_csv, mapping, T["machines"], T["alarm_definitions"])
    T["alarm_events"] = ing["valid"]
    known = {e["alarm_event_id"] for e in ing["valid"]}
    orphan_acks = sum(1 for a in T["acknowledgements"] if a["alarm_event_id"] not in known)
    ing["summary"]["acknowledgements_without_ingested_event"] = orphan_acks

    anomalies = detect_anomalies(T)
    as_of = max((e["event_ts"] for e in ing["valid"]), default=None)
    ops = classify_operations(T, anomalies)
    metrics = compute_metrics(T, ops, anomalies)
    ranking = metrics.pop("machine_risk_ranking")
    findings = build_findings(T, ops, anomalies)
    breakdowns = {r["machine_id"]: machine_risk_breakdown(r, ranking) for r in ranking}

    gt_path = os.path.join(out, "ground_truth", "ground_truth.csv")
    evaluation = None
    if os.path.exists(gt_path):   # synthetic data only; ground truth is read AFTER detection and never used by it
        evaluation = evaluate(anomalies, X.read_csv(gt_path), X.read_csv(os.path.join(out, "ground_truth", "ground_truth_controls.csv")))

    acks, cls = ops["acks"], {c["alarm_event_id"]: c for c in ops["classification"]}
    event_rows = []
    for e in T["alarm_events"]:
        c = cls[e["alarm_event_id"]]
        a = acks.get(e["alarm_event_id"])
        delay = int((X.parse_ts(a["ack_ts"]) - X.parse_ts(e["event_ts"])).total_seconds()) if a else None
        event_rows.append((e["alarm_event_id"], e["machine_id"], e["alarm_def_id"], e["event_ts"], e["clear_ts"], e["machine_state"], e["interlock_state"],
                           c["classification"], c["flags"], a["ack_id"] if a else None, a["ack_ts"] if a else None, delay))
    lc = {f["record_id"] for f in anomalies if f["rule_id"] == "R-LC-01"}
    src_actions = [(a["action_id"], a["incident_id"], a["machine_id"], a["action_type"], a["assigned_to"], a["verification_required"], a["status"],
                    a["opened_ts"], a["verified_ts"], a["verified_by"], a["closed_ts"], int(a["action_id"] in lc)) for a in T["corrective_actions"]]

    by_rule = {}
    for f in findings:
        by_rule[f["rule_id"]] = by_rule.get(f["rule_id"], 0) + 1
    summary = dict(ingest=ing["summary"], as_of=as_of, findings_by_rule=dict(sorted(by_rule.items())), evaluation=evaluation,
                   kpis=dict(scale=metrics["scale"], corrective_actions=metrics["corrective_actions"], alarm_floods=metrics["alarm_floods"],
                             nuisance_alarms=metrics["nuisance_alarms"], acknowledgement_response=metrics["acknowledgement_response"]),
                   duplicate_events_flagged=sum(1 for f in anomalies if f["rule_id"] == "R-DU-01"))
    digest = hashlib.sha256(json.dumps(dict(f=findings, r=[(r["machine_id"], r["risk_score"], r["rank"]) for r in ranking],
                                            i={k: v for k, v in ing["summary"].items() if k != "source_file"}), sort_keys=True, default=str).encode()).hexdigest()
    res = dict(source=events_csv, T=T, ops=ops, anomalies=anomalies, findings=findings, machine_risk=ranking, breakdowns=breakdowns,
               rejects=ing["rejects"], n_events=len(ing["valid"]), event_rows=event_rows, source_action_rows=src_actions, summary=summary, digest=digest)
    if store_result:
        os.makedirs(os.path.join(out, "db"), exist_ok=True)
        con = store.connect(db_path(out))
        try:
            res["run_id"] = store.save_analysis(con, res)
        finally:
            con.close()
    return res

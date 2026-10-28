"""Read/write operations behind the dashboard. Every number returned here is queried from the SQLite workbench
(derived tables rebuilt by analysis.run_analysis + human workflow tables). No values are hard-coded."""
from __future__ import annotations

import json

from . import workflow as W
from .findings import RULE_CATALOG

SEVS = ("CRITICAL", "HIGH", "MEDIUM", "LOW")


def _rows(cur):
    return [dict(r) for r in cur]


def _last_run(con):
    r = con.execute("SELECT * FROM analysis_runs ORDER BY run_id DESC LIMIT 1").fetchone()
    return dict(r) if r else None


def run_info(con):
    r = _last_run(con)
    if not r:
        return None
    r["summary"] = json.loads(r.pop("summary_json"))
    return r


def resolutions(con):
    acts = {}
    for a in con.execute("SELECT * FROM wb_actions"):
        acts.setdefault(a["finding_id"], []).append(W.action_view(con, a))
    return {fid: W.finding_resolution(v)[0] for fid, v in acts.items()}


def _where(plant=None, machine=None, severity=None, rule=None, review=None, date_from=None, date_to=None, q=None, active_only=True):
    c, p = [], []
    if active_only:
        c.append("f.active=1")
    for col, v in (("f.plant_id", plant), ("f.machine_id", machine), ("f.severity", severity), ("f.rule_id", rule), ("r.review_status", review)):
        if v:
            c.append(f"{col}=?"); p.append(v)
    if date_from:
        c.append("f.window_end>=?"); p.append(date_from)
    if date_to:
        c.append("f.window_start<=?"); p.append(date_to + "T23:59:59Z" if len(date_to) == 10 else date_to)
    if q:
        c.append("(f.title LIKE ? OR f.finding_id LIKE ?)"); p += [f"%{q}%", f"%{q}%"]
    return (" WHERE " + " AND ".join(c)) if c else "", p


def findings_list(con, limit=500, offset=0, **flt):
    w, p = _where(**flt)
    res = resolutions(con)
    sql = f"""SELECT f.finding_id,f.rule_id,f.rule_name,f.category,f.plant_id,f.machine_id,f.title,f.severity,f.window_start,f.window_end,
              r.review_status, (SELECT COUNT(*) FROM finding_evidence e WHERE e.finding_id=f.finding_id AND e.role='TRIGGER') AS trigger_count
              FROM findings f JOIN review r USING(finding_id){w}
              ORDER BY CASE f.severity WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1 WHEN 'MEDIUM' THEN 2 ELSE 3 END, f.window_start DESC, f.finding_id"""
    allrows = _rows(con.execute(sql, p))
    for r in allrows:
        r["resolution"] = res.get(r["finding_id"], "NO_ACTION")
    return dict(total=len(allrows), items=allrows[offset:offset + limit])


def finding_detail(con, fid):
    f = con.execute("SELECT * FROM findings WHERE finding_id=?", (fid,)).fetchone()
    if not f:
        return None
    d = json.loads(f["detail_json"])
    d["active"] = bool(f["active"])
    d["evidence"] = _rows(con.execute("SELECT seq,record_type,record_id,ts,role,summary FROM finding_evidence WHERE finding_id=? ORDER BY seq", (fid,)))
    d["review"] = dict(con.execute("SELECT * FROM review WHERE finding_id=?", (fid,)).fetchone())
    acts = W.finding_actions(con, fid)
    d["actions"] = acts
    code, label = W.finding_resolution(acts)
    d["resolution"] = dict(code=code, label=label)
    mr = con.execute("SELECT breakdown_json, rank FROM machine_risk WHERE machine_id=?", (d["machine_id"],)).fetchone()
    d["machine_risk"] = dict(json.loads(mr["breakdown_json"]), rank=mr["rank"]) if mr else None
    return d


def overview(con, plant=None):
    pf, pp = ("WHERE plant_id=?", [plant]) if plant else ("", [])
    m = "SELECT machine_id FROM machines " + pf
    one = lambda sql, p=(): con.execute(sql, list(p)).fetchone()[0]
    run = run_info(con)
    asof = (run["summary"]["as_of"] or "")[:10] if run else ""
    fw = "WHERE f.active=1" + (" AND f.plant_id=?" if plant else "")
    sev = {s: 0 for s in SEVS}
    for r in con.execute(f"SELECT severity, COUNT(*) n FROM findings f {fw} GROUP BY severity", pp):
        sev[r["severity"]] = r["n"]
    rev = {s: 0 for s in W.REVIEW_STATES}
    for r in con.execute(f"SELECT r.review_status s, COUNT(*) n FROM findings f JOIN review r USING(finding_id) {fw} GROUP BY 1", pp):
        rev[r["s"]] = r["n"]
    res = resolutions(con)
    ids = {r[0] for r in con.execute(f"SELECT finding_id FROM findings f {fw}", pp)}
    rc = {}
    for fid in ids:
        rc[res.get(fid, "NO_ACTION")] = rc.get(res.get(fid, "NO_ACTION"), 0) + 1
    ev_filter = f"WHERE machine_id IN ({m})"
    wb = [W.action_view(con, a) for a in con.execute("SELECT * FROM wb_actions")]
    wb = [a for a in wb if (not plant or a["finding_id"] in ids)]
    src_unver = one(f"SELECT COUNT(*) FROM source_actions WHERE unverified_closure=1 AND machine_id IN ({m})", pp)
    out = dict(
        run=run, plant=plant,
        totals=dict(plants=1 if plant else one("SELECT COUNT(*) FROM plants"), machines=one(f"SELECT COUNT(*) FROM machines {pf}", pp),
                    alarm_events=one(f"SELECT COUNT(*) FROM events {ev_filter}", pp), incidents=one(f"SELECT COUNT(*) FROM incidents {ev_filter}", pp),
                    findings=sum(sev.values())),
        findings_by_severity=sev, findings_by_review=rev, findings_by_resolution=rc,
        high_risk_machines=_rows(con.execute(f"SELECT machine_id,plant_id,rank,risk_score FROM machine_risk {pf} ORDER BY risk_score DESC, machine_id LIMIT 8", pp)),
        alarm_volume_by_day=_rows(con.execute(f"SELECT substr(event_ts,1,10) day, COUNT(*) n FROM events {ev_filter} GROUP BY 1 ORDER BY 1", pp)),
        corrective_actions=dict(
            workbench_open=sum(1 for a in wb if a["status"] != "CLOSED"),
            workbench_overdue=sum(1 for a in wb if a["status"] != "CLOSED" and a["due_date"] and a["due_date"] < asof),
            workbench_closed_unverified=sum(1 for a in wb if a["closure_state"] == "CLOSED_UNVERIFIED"),
            source_closed_without_verification=src_unver,
            source_not_closed=one(f"SELECT COUNT(*) FROM source_actions WHERE status!='CLOSED' AND machine_id IN ({m})", pp)),
        data_quality=run["summary"]["ingest"] if run else None,
        evaluation=(run["summary"]["evaluation"] or {}).get("overall") if run else None,
    )
    return out


def machines(con, plant=None, severity=None, date_from=None, date_to=None, sort="risk", machine=None):
    """Risk score covers the whole analysed window; alarm/finding counts honour the date filter."""
    out = []
    for r in con.execute("SELECT mr.*, m.machine_name, m.machine_type, m.criticality FROM machine_risk mr JOIN machines m USING(machine_id)"):
        if plant and r["plant_id"] != plant or machine and r["machine_id"] != machine:
            continue
        row = json.loads(r["row_json"])
        ep, evp = ["machine_id=?"], [r["machine_id"]]
        if date_from:
            ep.append("event_ts>=?"); evp.append(date_from)
        if date_to:
            ep.append("event_ts<=?"); evp.append(date_to + "T23:59:59Z")
        n_alarms = con.execute("SELECT COUNT(*) FROM events WHERE " + " AND ".join(ep), evp).fetchone()[0]
        w, p = _where(machine=r["machine_id"], severity=severity, date_from=date_from, date_to=date_to)
        nf = con.execute(f"SELECT COUNT(*) FROM findings f JOIN review r USING(finding_id){w}", p).fetchone()[0]
        if severity and nf == 0:
            continue
        out.append(dict(machine_id=r["machine_id"], machine_name=r["machine_name"], machine_type=r["machine_type"], plant_id=r["plant_id"], criticality=r["criticality"],
                        risk_score=r["risk_score"], rank=r["rank"], alarms_in_range=n_alarms, findings_in_range=nf,
                        unsafe_events=row["unsafe_events"], unacknowledged=row["unacknowledged"]))
    out.sort(key=(lambda x: (-x["risk_score"], x["machine_id"])) if sort == "risk" else (lambda x: (-x["findings_in_range"], x["machine_id"])))
    return out


def machine_detail(con, mid):
    r = con.execute("SELECT mr.*, m.machine_name, m.machine_type FROM machine_risk mr JOIN machines m USING(machine_id) WHERE machine_id=?", (mid,)).fetchone()
    if not r:
        return None
    return dict(machine_id=mid, machine_name=r["machine_name"], machine_type=r["machine_type"], plant_id=r["plant_id"], rank=r["rank"],
                breakdown=json.loads(r["breakdown_json"]),
                findings=findings_list(con, machine=mid, limit=200)["items"],
                recent_events=_rows(con.execute("""SELECT e.*, d.alarm_code, d.severity FROM events e JOIN alarm_defs d USING(alarm_def_id)
                                                   WHERE machine_id=? ORDER BY event_ts DESC, alarm_event_id LIMIT 100""", (mid,))),
                alarms_by_day=_rows(con.execute("SELECT substr(event_ts,1,10) day, COUNT(*) n FROM events WHERE machine_id=? GROUP BY 1 ORDER BY 1", (mid,))))


def actions(con):
    run = run_info(con)
    asof = (run["summary"]["as_of"] or "")[:10] if run else ""
    wb = [W.action_view(con, a) for a in con.execute("SELECT * FROM wb_actions ORDER BY wb_action_id")]
    for a in wb:
        a["overdue"] = bool(a["status"] != "CLOSED" and a["due_date"] and a["due_date"] < asof)
    src = _rows(con.execute("SELECT * FROM source_actions WHERE unverified_closure=1 ORDER BY action_id"))
    return dict(workbench=wb, source_unverified_closures=src, as_of=asof)


def events(con, machine=None, date_from=None, date_to=None, limit=200):
    c, p = ["1=1"], []
    if machine:
        c.append("machine_id=?"); p.append(machine)
    if date_from:
        c.append("event_ts>=?"); p.append(date_from)
    if date_to:
        c.append("event_ts<=?"); p.append(date_to + "T23:59:59Z")
    return _rows(con.execute(f"SELECT e.*, d.alarm_code, d.severity FROM events e JOIN alarm_defs d USING(alarm_def_id) WHERE {' AND '.join(c)} ORDER BY event_ts LIMIT ?", p + [limit]))


def quality(con):
    run = run_info(con)
    return dict(summary=run["summary"]["ingest"] if run else None, duplicate_events_flagged=run["summary"]["duplicate_events_flagged"] if run else 0, rejects=_rows(con.execute("SELECT * FROM ingest_rejects ORDER BY source_line")))


def evaluation(con):
    run = run_info(con)
    ev = run["summary"]["evaluation"] if run else None
    return dict(available=ev is not None, evaluation=ev,
                note="Ground truth exists only for the synthetic dataset and is read after detection. Rules without injected ground truth (flood, nuisance, repeated alarms, ack pattern, repeated incidents) are NOT scored here.")


def rules():
    return [dict(rule_id=k, **v) for k, v in RULE_CATALOG.items()]


def plants(con):
    return _rows(con.execute("SELECT * FROM plants ORDER BY plant_id"))

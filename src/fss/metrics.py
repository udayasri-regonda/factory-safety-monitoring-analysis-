"""KPIs computed from the generated records, evaluation against ground truth, and the HTML dashboard."""
from __future__ import annotations

import html
import statistics
from collections import Counter, defaultdict

from .exporters import parse_ts
from . import config as C


def _pct(vals, q):
    if not vals:
        return None
    s = sorted(vals)
    return s[min(len(s) - 1, int(round(q * (len(s) - 1))))]


def _r(x, n=1):
    return None if x is None else round(x, n)


def compute_metrics(T, ops, anomalies):
    defs, flags, events, acks = ops["defs"], ops["flags"], ops["events"], ops["acks"]
    mach = {m["machine_id"]: m for m in T["machines"]}
    shifts = {s["shift_id"]: s for s in T["operator_shifts"]}
    n_ev = len(events)

    # ---- response time
    resp = []
    for e in events:
        a = acks.get(e["alarm_event_id"])
        if a:
            resp.append((e, a, (parse_ts(a["ack_ts"]) - e["_t"]).total_seconds()))

    def stats(items):
        v = [x[2] for x in items]
        sla_ok = sum(1 for x in items if x[2] <= defs[x[0]["alarm_def_id"]]["ack_sla_seconds"])
        return dict(acknowledged=len(v), median_s=_r(statistics.median(v)) if v else None, p90_s=_r(_pct(v, .9)),
                    p95_s=_r(_pct(v, .95)), sla_compliance_pct=_r(100 * sla_ok / len(v)) if v else None)

    by_sev = {s: stats([x for x in resp if defs[x[0]["alarm_def_id"]]["severity"] == s]) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW")}
    by_plant = {p["plant_id"]: stats([x for x in resp if mach[x[0]["machine_id"]]["plant_id"] == p["plant_id"]]) for p in T["plants"]}
    by_shift = {}
    for sn in ("MORNING", "AFTERNOON", "NIGHT"):
        by_shift[sn] = stats([x for x in resp if shifts[x[1]["shift_id"]]["shift_name"] == sn])
    sev_events = Counter(defs[e["alarm_def_id"]]["severity"] for e in events)
    unack_hc = sum(1 for e in events if "UNACKNOWLEDGED" in flags[e["alarm_event_id"]])
    delayed = sum(1 for e in events if "DELAYED_ACK" in flags[e["alarm_event_id"]])

    # ---- nuisance
    nuis = [e for e in events if "NUISANCE_CHATTER" in flags[e["alarm_event_id"]]]
    nuis_by_def = Counter(e["alarm_def_id"] for e in nuis)

    # ---- machine risk ranking
    rows = []
    cnt = defaultdict(Counter)
    for e in events:
        for f in flags[e["alarm_event_id"]]:
            cnt[e["machine_id"]][f] += 1
        cnt[e["machine_id"]]["TOTAL"] += 1
        if defs[e["alarm_def_id"]]["severity"] in ("HIGH", "CRITICAL"):
            cnt[e["machine_id"]]["HC"] += 1
    for m in T["machines"]:
        c = cnt[m["machine_id"]]
        ru = ops["rec_unsafe"].get(m["machine_id"], {})
        score = sum(w * c[k] for k, w in C.RISK_WEIGHTS.items())
        rows.append(dict(machine_id=m["machine_id"], machine_name=m["machine_name"], plant_id=m["plant_id"], total_alarms=c["TOTAL"],
                         high_critical_alarms=c["HC"], unsafe_events=c["UNSAFE_CONDITION"], max_unsafe_in_7d=ru.get("max_unsafe_in_window", 0),
                         recurring_unsafe=int(ru.get("recurring", False)), recurring_alarm_events=c["RECURRING_ALARM"],
                         delayed_acks=c["DELAYED_ACK"], unacknowledged=c["UNACKNOWLEDGED"], flood_events=c["ALARM_FLOOD"],
                         nuisance_events=c["NUISANCE_CHATTER"], risk_score=round(score, 1)))
    rows.sort(key=lambda r: (-r["risk_score"], r["machine_id"]))
    for i, r in enumerate(rows, 1):
        r["rank"] = i

    # ---- alarms requiring attention
    per_def = defaultdict(Counter)
    for e in events:
        c = per_def[e["alarm_def_id"]]
        c["n"] += 1
        for f in flags[e["alarm_event_id"]]:
            c[f] += 1
    attn = []
    for did, c in per_def.items():
        d = defs[did]
        w = {"CRITICAL": 4, "HIGH": 2, "MEDIUM": 1, "LOW": 0.5}[d["severity"]]
        attn.append(dict(alarm_def_id=did, alarm_code=d["alarm_code"], severity=d["severity"], events=c["n"],
                         unsafe=c["UNSAFE_CONDITION"], delayed=c["DELAYED_ACK"], unacknowledged=c["UNACKNOWLEDGED"],
                         recurring=c["RECURRING_ALARM"], score=round(w * (c["n"] + 3 * c["UNSAFE_CONDITION"] + 2 * c["UNACKNOWLEDGED"] + c["DELAYED_ACK"]), 1)))
    attn.sort(key=lambda r: -r["score"])

    # ---- corrective action verification
    acts = T["corrective_actions"]
    closed = [a for a in acts if a["status"] == "CLOSED"]
    closed_req = [a for a in closed if a["verification_required"] == 1]
    ok = [a for a in closed_req if a["verified_ts"] and a["verified_by"]]
    open_acts = [a for a in acts if a["status"] != "CLOSED"]
    lc_flagged = sum(1 for f in anomalies if f["rule_id"] == "R-LC-01")

    return dict(
        scale=dict(plants=len(T["plants"]), machines=len(T["machines"]), alarm_definitions=len(T["alarm_definitions"]),
                   alarm_events_stored=len(T["alarm_events"]), alarm_events_after_dedup=n_ev,
                   duplicate_replays_removed=len(T["alarm_events"]) - n_ev, incidents=len(T["incidents"]), corrective_actions=len(acts)),
        recurring_unsafe_conditions=dict(
            machines_with_recurring_unsafe=sum(1 for v in ops["rec_unsafe"].values() if v["recurring"]),
            machines_with_any_unsafe=sum(1 for v in ops["rec_unsafe"].values() if v["unsafe_total"]),
            unsafe_events=sum(1 for e in events if "UNSAFE_CONDITION" in flags[e["alarm_event_id"]]),
            recurring_alarm_groups=len(ops["recurring"]),
            rule=f">= {C.RULES['recurring_unsafe_min_events']} UNSAFE events on one machine within {C.RULES['recurring_unsafe_window_days']} days"),
        acknowledgement_response=dict(overall=stats(resp), by_severity=by_sev, by_plant=by_plant, by_shift=by_shift,
                                      delayed_acks=delayed, high_critical_unacknowledged=unack_hc,
                                      unacknowledged_pct_high_critical=_r(100 * unack_hc / max(1, sev_events["HIGH"] + sev_events["CRITICAL"]))),
        nuisance_alarms=dict(nuisance_events=len(nuis), nuisance_rate_pct=_r(100 * len(nuis) / max(1, n_ev), 2),
                             top_definitions=[dict(alarm_def_id=k, alarm_code=defs[k]["alarm_code"], events=v) for k, v in nuis_by_def.most_common(5)],
                             rule=f">= {C.RULES['chatter_min_repeats']} repeats of a LOW/MEDIUM alarm on one machine within {C.RULES['chatter_window_s']}s"),
        alarm_floods=dict(episodes=len(ops["floods"]), alarms_in_floods=sum(len(f["ids"]) for f in ops["floods"]),
                          rule=f">= {C.RULES['flood_min_alarms']} alarms on one machine within {C.RULES['flood_window_s']}s"),
        corrective_actions=dict(total=len(acts), closed=len(closed), closed_requiring_verification=len(closed_req),
                                closed_with_verification=len(ok),
                                verification_rate_pct=_r(100 * len(ok) / len(closed_req), 2) if closed_req else None,
                                still_open=len(open_acts), lifecycle_violations_flagged=lc_flagged),
        top_risk_machines=rows[:10], machine_risk_ranking=rows, alarms_requiring_attention=attn[:15],
    )


# ----------------------------------------------------------------------------- evaluation
def evaluate(anomalies, gt_rows, ctl_rows):
    gt = {(g["anomaly_type"], g["record_id"]) for g in gt_rows}
    pred = {(f["anomaly_type"], f["record_id"]) for f in anomalies}
    types = sorted({g["anomaly_type"] for g in gt_rows} | {f["anomaly_type"] for f in anomalies})
    rows = []

    def prf(tp, fp, fn):
        p = tp / (tp + fp) if tp + fp else 1.0
        r = tp / (tp + fn) if tp + fn else 1.0
        return p, r, (2 * p * r / (p + r) if p + r else 0.0)

    for t in types:
        g = {k for k in gt if k[0] == t}
        d = {k for k in pred if k[0] == t}
        tp, fp, fn = len(g & d), len(d - g), len(g - d)
        p, r, f1 = prf(tp, fp, fn)
        rows.append(dict(anomaly_type=t, injected=len(g), detected=len(d), true_positives=tp, false_positives=fp,
                         false_negatives=fn, precision=round(p, 4), recall=round(r, 4), f1=round(f1, 4)))
    tp, fp, fn = len(gt & pred), len(pred - gt), len(gt - pred)
    p, r, f1 = prf(tp, fp, fn)
    ctl_ids = {(c["table"], c["record_id"]) for c in ctl_rows}
    flagged_ids = {(f["table"], f["record_id"]) for f in anomalies}
    return dict(per_type=rows, overall=dict(injected=len(gt), detected=len(pred), true_positives=tp, false_positives=fp,
                                            false_negatives=fn, precision=round(p, 4), recall=round(r, 4), f1=round(f1, 4)),
                controls=dict(total=len(ctl_ids), wrongly_flagged=len(ctl_ids & flagged_ids)),
                missed=sorted(gt - pred)[:50], false_positive_examples=sorted(pred - gt)[:50])


def evaluation_md(ev):
    o = ev["overall"]
    L = ["# Anomaly Detection Evaluation", "",
         "The detector ran on the data tables only. Labels in `ground_truth/` were used here, after detection, to score it.", "",
         f"**Overall:** injected {o['injected']}, detected {o['detected']}, TP {o['true_positives']}, FP {o['false_positives']}, "
         f"FN {o['false_negatives']} -> precision **{o['precision']:.2%}**, recall **{o['recall']:.2%}**, F1 **{o['f1']:.2%}**.", "",
         f"**Hard-negative controls:** {ev['controls']['total']} look-alike valid records, {ev['controls']['wrongly_flagged']} wrongly flagged.", "",
         "| Anomaly type | Injected | Detected | TP | FP | FN | Precision | Recall | F1 |", "|---|---:|---:|---:|---:|---:|---:|---:|---:|"]
    for r in ev["per_type"]:
        L.append(f"| {r['anomaly_type']} | {r['injected']} | {r['detected']} | {r['true_positives']} | {r['false_positives']} | "
                 f"{r['false_negatives']} | {r['precision']:.2%} | {r['recall']:.2%} | {r['f1']:.2%} |")
    if ev["missed"]:
        L += ["", "Missed (first 50): " + ", ".join(f"{t}:{i}" for t, i in ev["missed"])]
    if ev["false_positive_examples"]:
        L += ["", "False positives (first 50): " + ", ".join(f"{t}:{i}" for t, i in ev["false_positive_examples"])]
    return "\n".join(L) + "\n"


def summary_md(m, ev=None):
    s, r, a = m["scale"], m["acknowledgement_response"], m["corrective_actions"]
    L = ["# Safety Analytics Summary", "", "All figures are computed from the generated records (duplicates removed, invalid acknowledgements excluded).", "",
         f"- Stored alarm events: **{s['alarm_events_stored']:,}** ({s['duplicate_replays_removed']} replayed duplicates removed -> {s['alarm_events_after_dedup']:,} analysed)",
         f"- Machines with recurring unsafe conditions: **{m['recurring_unsafe_conditions']['machines_with_recurring_unsafe']}** of {s['machines']} "
         f"({m['recurring_unsafe_conditions']['rule']})",
         f"- Unsafe events (machine running while its safety interlock is disengaged): **{m['recurring_unsafe_conditions']['unsafe_events']:,}**",
         f"- Median acknowledgement time: **{r['overall']['median_s']} s**, p95 **{r['overall']['p95_s']} s**, SLA compliance **{r['overall']['sla_compliance_pct']}%**",
         f"- High/critical alarms never acknowledged: **{r['high_critical_unacknowledged']}** ({r['unacknowledged_pct_high_critical']}%)",
         f"- Nuisance alarm rate: **{m['nuisance_alarms']['nuisance_rate_pct']}%** ({m['nuisance_alarms']['nuisance_events']} events)",
         f"- Alarm floods: **{m['alarm_floods']['episodes']}** episodes covering {m['alarm_floods']['alarms_in_floods']} alarms",
         f"- Corrective-action verification rate (closed actions requiring verification that were verified): **{a['verification_rate_pct']}%** "
         f"({a['closed_with_verification']}/{a['closed_requiring_verification']})", "", "## Top 10 machines by risk score", "",
         "| Rank | Machine | Plant | Unsafe | Recurring alarm events | Delayed acks | Unacked | Floods | Risk |", "|---:|---|---|---:|---:|---:|---:|---:|---:|"]
    for x in m["top_risk_machines"]:
        L.append(f"| {x['rank']} | {x['machine_id']} {x['machine_name']} | {x['plant_id']} | {x['unsafe_events']} | {x['recurring_alarm_events']} | "
                 f"{x['delayed_acks']} | {x['unacknowledged']} | {x['flood_events']} | {x['risk_score']} |")
    L += ["", "## Alarm definitions needing attention (top 10)", "", "| Alarm | Severity | Events | Unsafe | Delayed | Unacked |", "|---|---|---:|---:|---:|---:|"]
    for x in m["alarms_requiring_attention"][:10]:
        L.append(f"| {x['alarm_code']} | {x['severity']} | {x['events']} | {x['unsafe']} | {x['delayed']} | {x['unacknowledged']} |")
    L += ["", "## Acknowledgement response by severity", "", "| Severity | Acked | Median s | p90 s | p95 s | SLA met % |", "|---|---:|---:|---:|---:|---:|"]
    for k, v in r["by_severity"].items():
        L.append(f"| {k} | {v['acknowledged']} | {v['median_s']} | {v['p90_s']} | {v['p95_s']} | {v['sla_compliance_pct']} |")
    return "\n".join(L) + "\n"


# ----------------------------------------------------------------------------- dashboard
def dashboard_html(m, ev, validation_ok, repro=None):
    e = html.escape

    def table(head, rows):
        return "<table><tr>" + "".join(f"<th>{e(h)}</th>" for h in head) + "</tr>" + "".join(
            "<tr>" + "".join(f"<td>{e(str(c))}</td>" for c in r) + "</tr>" for r in rows) + "</table>"

    r, a, n = m["acknowledgement_response"], m["corrective_actions"], m["nuisance_alarms"]
    cards = [("Alarm events", f"{m['scale']['alarm_events_stored']:,}"), ("Median ack (s)", r["overall"]["median_s"]),
             ("SLA compliance", f"{r['overall']['sla_compliance_pct']}%"), ("Nuisance rate", f"{n['nuisance_rate_pct']}%"),
             ("Verification rate", f"{a['verification_rate_pct']}%"),
             ("Machines w/ recurring unsafe", m["recurring_unsafe_conditions"]["machines_with_recurring_unsafe"]),
             ("Detection recall", f"{ev['overall']['recall']:.1%}"), ("Detection precision", f"{ev['overall']['precision']:.1%}"),
             ("Structural validation", "PASS" if validation_ok else "FAIL")]
    if repro is not None:
        cards.append(("Reproducible", "YES" if repro else "NO"))
    css = ("body{font-family:system-ui,Segoe UI,Arial,sans-serif;margin:0;background:#f4f6f8;color:#1b2430}header{background:#13293d;color:#fff;padding:18px 28px}"
           "main{padding:20px 28px;max-width:1200px;margin:auto}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}"
           ".card{background:#fff;border-radius:8px;padding:14px;box-shadow:0 1px 3px #0002}.card b{display:block;font-size:24px;margin-top:6px}"
           "table{border-collapse:collapse;width:100%;background:#fff;margin:8px 0 24px;font-size:14px}th,td{border:1px solid #dde3ea;padding:6px 8px;text-align:left}"
           "th{background:#e8eef4}h2{margin-top:28px}")
    body = "".join(f'<div class="card">{e(k)}<b>{e(str(v))}</b></div>' for k, v in cards)
    top = table(["Rank", "Machine", "Plant", "Unsafe", "Recurring", "Delayed", "Unacked", "Floods", "Risk"],
                [[x["rank"], f"{x['machine_id']} {x['machine_name']}", x["plant_id"], x["unsafe_events"], x["recurring_alarm_events"], x["delayed_acks"],
                  x["unacknowledged"], x["flood_events"], x["risk_score"]] for x in m["top_risk_machines"]])
    att = table(["Alarm", "Severity", "Events", "Unsafe", "Delayed", "Unacked"],
                [[x["alarm_code"], x["severity"], x["events"], x["unsafe"], x["delayed"], x["unacknowledged"]] for x in m["alarms_requiring_attention"][:10]])
    sev = table(["Severity", "Acked", "Median s", "p90 s", "p95 s", "SLA met %"],
                [[k, v["acknowledged"], v["median_s"], v["p90_s"], v["p95_s"], v["sla_compliance_pct"]] for k, v in r["by_severity"].items()])
    evt = table(["Anomaly type", "Injected", "Detected", "TP", "FP", "FN", "Precision", "Recall"],
                [[x["anomaly_type"], x["injected"], x["detected"], x["true_positives"], x["false_positives"], x["false_negatives"],
                  f"{x['precision']:.1%}", f"{x['recall']:.1%}"] for x in ev["per_type"]])
    return (f"<!doctype html><html><head><meta charset='utf-8'><title>Factory Safety Dashboard</title><style>{css}</style></head><body>"
            f"<header><h1 style='margin:0'>Factory Safety Monitoring &amp; Analysis</h1></header><main><div class='cards'>{body}</div>"
            f"<h2>Top 10 machines by risk</h2>{top}<h2>Alarms requiring attention</h2>{att}<h2>Acknowledgement response by severity</h2>{sev}"
            f"<h2>Anomaly detection vs ground truth</h2>{evt}</main></body></html>")

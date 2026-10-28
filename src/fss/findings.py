"""Finding generation: turns detector output into investigable findings with stable IDs, severity, explanation and
chronological evidence. Findings are ADVISORY: they never operate or modify equipment.

Every finding separates `observed` (facts read from records) from `inferred` (interpretation a person must validate).
"""
from __future__ import annotations

import hashlib
from collections import defaultdict
from datetime import timedelta

from . import config as C
from .exporters import parse_ts

R = C.RULES
SEV_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

# ---- rule catalogue: single place that documents each rule (also rendered in the dashboard and docs) ----------
RULE_CATALOG = {
    "R-FLOOD-01": dict(code="FLOOD", name="Alarm flood", category="ALARM_FLOOD",
        logic=f">= {R['flood_min_alarms']} alarms on one machine within {R['flood_window_s']} s (ISA-18.2 style); overlapping windows merge into one episode.",
        severity="HIGH if the episode contains >= 3 HIGH/CRITICAL alarms, otherwise MEDIUM."),
    "R-NUIS-01": dict(code="NUIS", name="Nuisance chatter", category="NUISANCE_ALARM",
        logic=f">= {R['chatter_min_repeats']} repeats of the same LOW/MEDIUM (nuisance-candidate) alarm on one machine within {R['chatter_window_s']} s.",
        severity="MEDIUM if the episode has >= 10 events, otherwise LOW."),
    "R-REC-01": dict(code="RHSA", name="Repeated high-severity alarm", category="REPEATED_HIGH_SEVERITY",
        logic=f">= {R['recurring_min_events']} occurrences of the same HIGH/CRITICAL alarm on one machine within {R['recurring_window_days']} days.",
        severity="CRITICAL if the alarm definition is CRITICAL, otherwise HIGH."),
    "R-UNS-01": dict(code="UNSF", name="Recurring unsafe condition", category="UNSAFE_CONDITION",
        logic=f"An alarm raised while machine_state = RUNNING and interlock_state = DISENGAGED is UNSAFE; >= {R['recurring_unsafe_min_events']} on one machine within {R['recurring_unsafe_window_days']} days.",
        severity="CRITICAL if >= 5 events or any CRITICAL alarm is involved, otherwise HIGH."),
    "R-ACK-01": dict(code="ACKD", name="Acknowledgement delay / missing acknowledgement pattern", category="ACK_DELAY",
        logic=f">= {R['ack_pattern_min_events']} HIGH/CRITICAL alarms on one machine within {R['ack_pattern_window_days']} days that were acknowledged after their SLA or never acknowledged "
              f"(alarms younger than {R['unack_grace_s']} s at the end of the data are not counted as unacknowledged).",
        severity="HIGH if any CRITICAL alarm is unacknowledged or >= 5 events, otherwise MEDIUM."),
    "R-INC-02": dict(code="RINC", name="Repeated incidents on one machine", category="REPEATED_INCIDENTS",
        logic=f">= {R['repeat_incident_min']} incidents on one machine within {R['repeat_incident_window_days']} days.",
        severity="CRITICAL if any incident is CRITICAL, otherwise HIGH."),
    "R-LC-01": dict(code="LIFE", name="Corrective action closed without verification", category="UNVERIFIED_CLOSURE",
        logic="Action reached CLOSED while verification_required = 1 without a VERIFIED step / verified_ts / verified_by, or has an invalid status transition.",
        severity="HIGH if the linked incident is MAJOR/CRITICAL, otherwise MEDIUM."),
    "R-IN-01": dict(code="INEV", name="Incident without triggering evidence", category="EVIDENCE_GAP",
        logic="Incident has no triggering alarm event, the trigger belongs to another machine, or machine state at the incident is missing.",
        severity="HIGH if the incident is MAJOR/CRITICAL, otherwise MEDIUM."),
    "R-TL-01": dict(code="TIME", name="Acknowledgement earlier than its alarm", category="DATA_CONTRADICTION",
        logic="ack_ts < alarm event_ts (equal timestamps are valid).", severity="LOW (data-integrity issue; the acknowledgement is excluded from response-time statistics)."),
    "R-ST-01": dict(code="STAT", name="Impossible / contradictory interlock state", category="DATA_CONTRADICTION",
        logic="Interlock state contradicts the alarm definition, interlock belongs to another machine/type, or BYPASSED outside permitted machine states.",
        severity="HIGH if the alarm is CRITICAL, otherwise MEDIUM."),
}
ANOMALY_RULES = ("R-LC-01", "R-IN-01", "R-TL-01", "R-ST-01")      # one finding per flagged record

STEPS = {
    "ALARM_FLOOD": ["Review the alarm sequence in order; identify the first-out alarm.", "Check whether a single upstream cause (e.g. power, network, sensor) produced the burst.", "Review alarm rationalisation for the repeated alarms with the process owner."],
    "NUISANCE_ALARM": ["Inspect the sensor / setpoint of the chattering alarm.", "Consider deadband or delay tuning through the site's management-of-change process."],
    "REPEATED_HIGH_SEVERITY": ["Inspect the machine and the alarmed function physically.", "Check maintenance history for the same fault.", "Confirm whether a corrective action already exists for this alarm."],
    "UNSAFE_CONDITION": ["Ask the shift supervisor whether the machine was running with the protective device open or bypassed.", "Inspect the interlock / guard physically.", "Verify the machine_state and interlock_state signals are correct before drawing conclusions."],
    "ACK_DELAY": ["Review staffing and alarm routing for the affected shifts.", "Check whether the alarms were visible at the operator station.", "Interview the operators involved."],
    "REPEATED_INCIDENTS": ["Review the incident records together for a common cause.", "Check whether earlier corrective actions were verified effective."],
    "UNVERIFIED_CLOSURE": ["Obtain verification evidence from the responsible supervisor, or reopen the action.", "Do not treat the underlying hazard as resolved until verification is recorded."],
    "EVIDENCE_GAP": ["Complete the incident record (trigger alarm and machine state) from operator statements / logs.", "Treat conclusions about this incident as provisional."],
    "DATA_CONTRADICTION": ["Check the source system and the time synchronisation of the clocks involved.", "Correct or annotate the source record; the system never edits source data."],
}


def _sha(*parts):
    return hashlib.sha1("|".join(str(p) for p in parts).encode()).hexdigest()


def finding_id(rule_id, machine_id, anchor):
    return f"F-{RULE_CATALOG[rule_id]['code']}-{_sha(rule_id, machine_id, anchor)[:8].upper()}"


def episodes(items, window, min_n, ts, key):
    """Sliding-window clustering. Returns time-ordered lists of items; overlapping qualifying windows are merged."""
    items = sorted(items, key=lambda x: (ts(x), key(x)))
    out, cur_start, cur_end, k = [], None, -1, 0
    for j in range(len(items)):
        k = max(k, j)
        while k + 1 < len(items) and ts(items[k + 1]) - ts(items[j]) <= window:
            k += 1
        if k - j + 1 >= min_n:
            if cur_start is not None and j <= cur_end:
                cur_end = max(cur_end, k)
            else:
                if cur_start is not None:
                    out.append(items[cur_start:cur_end + 1])
                cur_start, cur_end = j, k
    if cur_start is not None:
        out.append(items[cur_start:cur_end + 1])
    return out


def machine_risk_breakdown(row, ranking):
    """Explain a machine's risk score: components (count x weight), plus fleet/plant baselines."""
    comps = []
    keymap = {"UNSAFE_CONDITION": "unsafe_events", "RECURRING_ALARM": "recurring_alarm_events", "DELAYED_ACK": "delayed_acks",
              "UNACKNOWLEDGED": "unacknowledged", "ALARM_FLOOD": "flood_events"}
    for k, w in C.RISK_WEIGHTS.items():
        n = row[keymap[k]]
        comps.append(dict(factor=k, label=C.RISK_LABELS[k], count=n, weight=w, points=round(n * w, 1)))
    scores = sorted(r["risk_score"] for r in ranking)
    plant = sorted(r["risk_score"] for r in ranking if r["plant_id"] == row["plant_id"])

    def med(v):
        return v[len(v) // 2] if len(v) % 2 else (v[len(v) // 2 - 1] + v[len(v) // 2]) / 2
    below = sum(1 for s in scores if s < row["risk_score"])
    return dict(machine_id=row["machine_id"], score=row["risk_score"], components=comps,
                total_alarms=row["total_alarms"], fleet_size=len(ranking), fleet_median_score=med(scores), plant_median_score=med(plant),
                percentile_in_fleet=round(100 * below / max(1, len(scores)), 1),
                interpretation="Relative ranking index built from the weighted counts above. It is NOT a probability of an accident and has not been calibrated against outcomes.")


class _Ctx:
    def __init__(self, T, ops, anomalies):
        self.T, self.ops, self.an = T, ops, anomalies
        self.mach = {m["machine_id"]: m for m in T["machines"]}
        self.defs = ops["defs"]
        self.ev = {e["alarm_event_id"]: e for e in T["alarm_events"]}
        self.flags = ops["flags"]
        self.acks_all = defaultdict(list)
        for a in T["acknowledgements"]:
            self.acks_all[a["alarm_event_id"]].append(a)
        self.inc = {i["incident_id"]: i for i in T["incidents"]}
        self.inc_by_trigger = defaultdict(list)
        for i in T["incidents"]:
            if i["trigger_alarm_event_id"]:
                self.inc_by_trigger[i["trigger_alarm_event_id"]].append(i)
        self.act_by_inc = defaultdict(list)
        self.act = {a["action_id"]: a for a in T["corrective_actions"]}
        for a in T["corrective_actions"]:
            self.act_by_inc[a["incident_id"]].append(a)
        self.hist = defaultdict(list)
        for h in T["corrective_action_history"]:
            self.hist[h["action_id"]].append(h)
        self.bad_ack = {f["record_id"]: f for f in self.an if f["rule_id"] == "R-TL-01"}
        self.susp = {f["record_id"]: f for f in self.an if f["rule_id"] == "R-ST-01"}
        self.by_machine = defaultdict(list)
        for e in ops["events"]:
            self.by_machine[e["machine_id"]].append(e)
        for lst in self.by_machine.values():
            lst.sort(key=lambda e: (e["_t"], e["alarm_event_id"]))

    def sev(self, e):
        return self.defs[e["alarm_def_id"]]["severity"]

    def plant(self, machine_id):
        return self.mach[machine_id]["plant_id"]


def _ev_entry(c, e, role):
    d = c.defs[e["alarm_def_id"]]
    fl = sorted(c.flags.get(e["alarm_event_id"], []))
    return dict(record_type="ALARM_EVENT", record_id=e["alarm_event_id"], ts=e["event_ts"], role=role,
                summary=f"{d['alarm_code']} [{d['severity']}] machine_state={e['machine_state']} interlock_state={e['interlock_state']}"
                        + (f" flags={'|'.join(fl)}" if fl else ""))


def _ack_entries(c, eids):
    out, missing = [], []
    for eid in eids:
        a = c.acks_all.get(eid)
        if not a:
            missing.append(eid)
            continue
        for k in a:
            delay = int((parse_ts(k["ack_ts"]) - parse_ts(c.ev[eid]["event_ts"])).total_seconds())
            out.append(dict(record_type="ACKNOWLEDGEMENT", record_id=k["ack_id"], ts=k["ack_ts"], role="ACKNOWLEDGEMENT",
                            summary=f"acknowledges {eid} by {k['operator_id']} via {k['ack_method']}; delay {delay}s"
                                    + (" (CONTRADICTION: before alarm)" if k["ack_id"] in c.bad_ack else "")))
    return out, missing


def _inc_action_entries(c, eids, machine_id, w0, w1):
    out, seen = [], set()
    cand = [i for e in eids for i in c.inc_by_trigger.get(e, [])]
    cand += [i for i in c.T["incidents"] if i["machine_id"] == machine_id and w0 <= parse_ts(i["opened_ts"]) <= w1 + timedelta(hours=24)]
    for i in cand:
        if i["incident_id"] in seen:
            continue
        seen.add(i["incident_id"])
        out.append(dict(record_type="INCIDENT", record_id=i["incident_id"], ts=i["opened_ts"], role="RELATED_INCIDENT",
                        summary=f"{i['incident_type']} [{i['severity']}] status={i['status']}; trigger={i['trigger_alarm_event_id'] or 'EVIDENCE UNAVAILABLE'}"))
        for a in c.act_by_inc.get(i["incident_id"], []):
            out.append(dict(record_type="CORRECTIVE_ACTION", record_id=a["action_id"], ts=a["opened_ts"], role="RELATED_ACTION",
                            summary=f"{a['action_type']} status={a['status']} verification_required={a['verification_required']} "
                                    f"verified_by={a['verified_by'] or 'none'}"))
    return out


def _context(c, machine_id, w0, w1, exclude):
    n = R["context_events_each_side"]
    lst = c.by_machine[machine_id]
    before = [e for e in lst if e["_t"] < w0 and e["alarm_event_id"] not in exclude][-n:]
    after = [e for e in lst if e["_t"] > w1 and e["alarm_event_id"] not in exclude][:n]
    return [_ev_entry(c, e, "CONTEXT_BEFORE") for e in before] + [_ev_entry(c, e, "CONTEXT_AFTER") for e in after]


def _event_missing(c, eids, ack_missing):
    miss, contra = [], []
    hs_unack = [e for e in ack_missing if c.sev(c.ev[e]) in ("HIGH", "CRITICAL")]
    if ack_missing:
        miss.append(f"No acknowledgement record for {len(ack_missing)} of {len(eids)} triggering events"
                    + (f" ({len(hs_unack)} HIGH/CRITICAL): " + ", ".join(ack_missing[:5]) + (" ..." if len(ack_missing) > 5 else "") if ack_missing else ""))
    unk = [e for e in eids if c.ev[e]["machine_state"] == "UNKNOWN"]
    if unk:
        miss.append(f"machine_state not provided by the source for {len(unk)} event(s): Evidence unavailable")
    need_inc = [e for e in eids if c.defs[c.ev[e]["alarm_def_id"]]["requires_incident"] == "1" or c.defs[c.ev[e]["alarm_def_id"]]["requires_incident"] == 1]
    no_inc = [e for e in need_inc if e not in c.inc_by_trigger]
    if no_inc:
        miss.append(f"Alarm definition requires an incident record but none is linked for: " + ", ".join(no_inc[:5]) + (" ..." if len(no_inc) > 5 else ""))
    for e in eids:
        if e in c.susp:
            contra.append(f"{e}: {c.susp[e]['reason']}")
        for a in c.acks_all.get(e, []):
            if a["ack_id"] in c.bad_ack:
                contra.append(f"{a['ack_id']}: {c.bad_ack[a['ack_id']]['reason']}")
    return miss, contra


def _mk(c, rule_id, machine_id, anchor, title, severity, rationale, w0, w1, observed, inferred, params, evidence, missing, contradictions):
    cat = RULE_CATALOG[rule_id]["category"]
    evidence = sorted(evidence, key=lambda x: (x["ts"] or "", x["record_type"], x["record_id"]))
    return dict(finding_id=finding_id(rule_id, machine_id, anchor), rule_id=rule_id, rule_name=RULE_CATALOG[rule_id]["name"],
                category=cat, plant_id=c.plant(machine_id), machine_id=machine_id, title=title, severity=severity,
                severity_rationale=rationale, rule_logic=RULE_CATALOG[rule_id]["logic"], window_start=w0.strftime("%Y-%m-%dT%H:%M:%SZ"),
                window_end=w1.strftime("%Y-%m-%dT%H:%M:%SZ"), observed=observed, inferred=inferred, params=params,
                evidence=evidence, missing_evidence=missing, contradictions=contradictions,
                recommended_steps=STEPS[cat], anchor=anchor,
                trigger_event_ids=[x["record_id"] for x in evidence if x["role"] == "TRIGGER"],
                advisory="Advisory only. Requires validation by qualified personnel before any action; the system never operates equipment.")


def _episode_finding(c, rule_id, machine_id, evs, title, severity, rationale, observed, inferred, params):
    eids = [e["alarm_event_id"] for e in evs]
    w0, w1 = evs[0]["_t"], evs[-1]["_t"]
    ack_e, ack_missing = _ack_entries(c, eids)
    evidence = [_ev_entry(c, e, "TRIGGER") for e in evs] + ack_e + _inc_action_entries(c, eids, machine_id, w0, w1) + _context(c, machine_id, w0, w1, set(eids))
    miss, contra = _event_missing(c, eids, ack_missing)
    return _mk(c, rule_id, machine_id, evs[0]["alarm_event_id"], title, severity, rationale, w0, w1, observed, inferred, params, evidence, miss, contra)


def build_findings(T, ops, anomalies):
    c = _Ctx(T, ops, anomalies)
    out = []
    ev = ops["events"]
    by_m = c.by_machine

    # --- alarm floods
    for m, lst in sorted(by_m.items()):
        for ep in episodes(lst, timedelta(seconds=R["flood_window_s"]), R["flood_min_alarms"], lambda e: e["_t"], lambda e: e["alarm_event_id"]):
            hs = sum(1 for e in ep if c.sev(e) in ("HIGH", "CRITICAL"))
            sev = "HIGH" if hs >= 3 else "MEDIUM"
            dur = int((ep[-1]["_t"] - ep[0]["_t"]).total_seconds())
            out.append(_episode_finding(c, "R-FLOOD-01", m, ep, f"Alarm flood on {m}: {len(ep)} alarms in {dur}s", sev,
                f"{hs} HIGH/CRITICAL alarms in the episode (threshold for HIGH is 3).",
                [f"{len(ep)} alarm events on {m} between {ep[0]['event_ts']} and {ep[-1]['event_ts']}.", f"{hs} of them are HIGH/CRITICAL; {len({e['alarm_def_id'] for e in ep})} distinct alarm definitions."],
                "A burst of this size usually exceeds what an operator can process; it may hide a first-out cause or indicate a common upstream fault. This is an interpretation, not a confirmed cause.",
                dict(window_s=R["flood_window_s"], min_alarms=R["flood_min_alarms"], alarm_count=len(ep))))

    # --- nuisance chatter (per machine + definition)
    grp = defaultdict(list)
    for e in ev:
        if str(c.defs[e["alarm_def_id"]]["nuisance_candidate"]) == "1":
            grp[(e["machine_id"], e["alarm_def_id"])].append(e)
    for (m, d), lst in sorted(grp.items()):
        for ep in episodes(lst, timedelta(seconds=R["chatter_window_s"]), R["chatter_min_repeats"], lambda e: e["_t"], lambda e: e["alarm_event_id"]):
            sev = "MEDIUM" if len(ep) >= 10 else "LOW"
            code = c.defs[d]["alarm_code"]
            out.append(_episode_finding(c, "R-NUIS-01", m, ep, f"Nuisance chatter: {code} x{len(ep)} on {m}", sev, f"{len(ep)} events (MEDIUM from 10).",
                [f"{len(ep)} repeats of {code} on {m} between {ep[0]['event_ts']} and {ep[-1]['event_ts']}."],
                "Rapid repeats of a low-priority alarm are typical of a noisy sensor or a badly tuned setpoint (interpretation).",
                dict(window_s=R["chatter_window_s"], min_repeats=R["chatter_min_repeats"], alarm_def_id=d)))

    # --- repeated HIGH/CRITICAL alarms (per machine + definition)
    grp = defaultdict(list)
    for e in ev:
        if c.sev(e) in ("HIGH", "CRITICAL"):
            grp[(e["machine_id"], e["alarm_def_id"])].append(e)
    for (m, d), lst in sorted(grp.items()):
        for ep in episodes(lst, timedelta(days=R["recurring_window_days"]), R["recurring_min_events"], lambda e: e["_t"], lambda e: e["alarm_event_id"]):
            sev = "CRITICAL" if c.defs[d]["severity"] == "CRITICAL" else "HIGH"
            code = c.defs[d]["alarm_code"]
            out.append(_episode_finding(c, "R-REC-01", m, ep, f"Repeated {c.defs[d]['severity']} alarm {code} x{len(ep)} on {m}", sev,
                f"Alarm definition {d} has severity {c.defs[d]['severity']}.",
                [f"{len(ep)} occurrences of {code} on {m} between {ep[0]['event_ts']} and {ep[-1]['event_ts']} (window {R['recurring_window_days']} days)."],
                "Repetition suggests the underlying condition is not being cleared at its root cause (interpretation).",
                dict(window_days=R["recurring_window_days"], min_events=R["recurring_min_events"], alarm_def_id=d)))

    # --- recurring unsafe condition (per machine)
    for m, lst in sorted(by_m.items()):
        un = [e for e in lst if "UNSAFE_CONDITION" in c.flags.get(e["alarm_event_id"], ())]
        for ep in episodes(un, timedelta(days=R["recurring_unsafe_window_days"]), R["recurring_unsafe_min_events"], lambda e: e["_t"], lambda e: e["alarm_event_id"]):
            crit = any(c.sev(e) == "CRITICAL" for e in ep)
            sev = "CRITICAL" if (len(ep) >= 5 or crit) else "HIGH"
            out.append(_episode_finding(c, "R-UNS-01", m, ep, f"Recurring unsafe condition on {m}: {len(ep)} events", sev,
                f"{len(ep)} events (CRITICAL from 5); CRITICAL alarm involved: {'yes' if crit else 'no'}.",
                [f"{len(ep)} alarms on {m} between {ep[0]['event_ts']} and {ep[-1]['event_ts']} were raised with machine_state=RUNNING and interlock_state=DISENGAGED."],
                "If the signals are accurate, the machine ran with a protective interlock open. The signals themselves have not been independently verified.",
                dict(window_days=R["recurring_unsafe_window_days"], min_events=R["recurring_unsafe_min_events"])))

    # --- acknowledgement delay / missing acknowledgement (per machine)
    for m, lst in sorted(by_m.items()):
        bad = [e for e in lst if c.sev(e) in ("HIGH", "CRITICAL") and ({"DELAYED_ACK", "UNACKNOWLEDGED"} & c.flags.get(e["alarm_event_id"], set()))]
        for ep in episodes(bad, timedelta(days=R["ack_pattern_window_days"]), R["ack_pattern_min_events"], lambda e: e["_t"], lambda e: e["alarm_event_id"]):
            un = [e for e in ep if "UNACKNOWLEDGED" in c.flags[e["alarm_event_id"]]]
            crit_un = any(c.sev(e) == "CRITICAL" for e in un)
            sev = "HIGH" if (crit_un or len(ep) >= 5) else "MEDIUM"
            out.append(_episode_finding(c, "R-ACK-01", m, ep, f"Acknowledgement problems on {m}: {len(ep)} HIGH/CRITICAL alarms ({len(un)} unacknowledged)", sev,
                f"{len(un)} unacknowledged (CRITICAL unacknowledged: {'yes' if crit_un else 'no'}); HIGH if CRITICAL unacknowledged or >= 5 events.",
                [f"{len(ep)} HIGH/CRITICAL alarms on {m} between {ep[0]['event_ts']} and {ep[-1]['event_ts']} were late or never acknowledged.", f"{len(un)} have no valid acknowledgement record."],
                "Possible causes include staffing, alarm routing, or missing acknowledgement capture. The data cannot distinguish these (interpretation).",
                dict(window_days=R["ack_pattern_window_days"], min_events=R["ack_pattern_min_events"], unacknowledged=len(un))))

    # --- repeated incidents (per machine)
    inc_by_m = defaultdict(list)
    for i in T["incidents"]:
        i["_t"] = parse_ts(i["opened_ts"])
        inc_by_m[i["machine_id"]].append(i)
    for m, lst in sorted(inc_by_m.items()):
        for ep in episodes(lst, timedelta(days=R["repeat_incident_window_days"]), R["repeat_incident_min"], lambda i: i["_t"], lambda i: i["incident_id"]):
            sev = "CRITICAL" if any(i["severity"] == "CRITICAL" for i in ep) else "HIGH"
            w0, w1 = ep[0]["_t"], ep[-1]["_t"]
            evidence, eids = [], [i["trigger_alarm_event_id"] for i in ep if i["trigger_alarm_event_id"] in c.ev]
            for i in ep:
                evidence.append(dict(record_type="INCIDENT", record_id=i["incident_id"], ts=i["opened_ts"], role="TRIGGER",
                                     summary=f"{i['incident_type']} [{i['severity']}] status={i['status']}; trigger={i['trigger_alarm_event_id'] or 'EVIDENCE UNAVAILABLE'}"))
                for a in c.act_by_inc.get(i["incident_id"], []):
                    evidence.append(dict(record_type="CORRECTIVE_ACTION", record_id=a["action_id"], ts=a["opened_ts"], role="RELATED_ACTION",
                                         summary=f"{a['action_type']} status={a['status']} verified_by={a['verified_by'] or 'none'}"))
            evidence += [_ev_entry(c, c.ev[e], "RELATED_ALARM") for e in eids]
            miss = [f"Incident {i['incident_id']} has no triggering alarm event: Evidence unavailable" for i in ep if not i["trigger_alarm_event_id"]]
            out.append(_mk(c, "R-INC-02", m, ep[0]["incident_id"], f"Repeated incidents on {m}: {len(ep)} in {R['repeat_incident_window_days']} days", sev,
                f"Most severe incident: {max((i['severity'] for i in ep), key=['MINOR','MODERATE','MAJOR','CRITICAL'].index)}.", w0, w1,
                [f"{len(ep)} incidents on {m} opened between {ep[0]['opened_ts']} and {ep[-1]['opened_ts']}: " + ", ".join(i["incident_id"] for i in ep)],
                "Repetition may mean earlier corrective actions did not remove the cause (interpretation; check verification status).",
                dict(window_days=R["repeat_incident_window_days"], min_incidents=R["repeat_incident_min"]), evidence, miss, []))

    # --- one finding per flagged record (data-evidence and lifecycle rules)
    for f in anomalies:
        rid, rule = f["record_id"], f["rule_id"]
        if rule not in ANOMALY_RULES:
            continue
        if rule == "R-LC-01":
            a = c.act[rid]
            inc = c.inc.get(a["incident_id"])
            sev = "HIGH" if inc and inc["severity"] in ("MAJOR", "CRITICAL") else "MEDIUM"
            w0 = parse_ts(a["opened_ts"])
            w1 = parse_ts(a["closed_ts"] or a["opened_ts"])
            evidence = [dict(record_type="CORRECTIVE_ACTION", record_id=rid, ts=a["opened_ts"], role="TRIGGER",
                             summary=f"{a['action_type']} assigned_to={a['assigned_to']} verification_required={a['verification_required']} status={a['status']} "
                                     f"verified_ts={a['verified_ts'] or 'MISSING'} verified_by={a['verified_by'] or 'MISSING'}")]
            for h in sorted(c.hist.get(rid, []), key=lambda h: h["seq"]):
                evidence.append(dict(record_type="ACTION_HISTORY", record_id=h["history_id"], ts=h["changed_ts"], role="HISTORY",
                                     summary=f"{h['from_status'] or '(new)'} -> {h['to_status']} by {h['changed_by']}"))
            if inc:
                evidence.append(dict(record_type="INCIDENT", record_id=inc["incident_id"], ts=inc["opened_ts"], role="RELATED_INCIDENT",
                                     summary=f"{inc['incident_type']} [{inc['severity']}] status={inc['status']}"))
            miss = []
            if not a["verified_ts"]:
                miss.append("Verification evidence unavailable (no verified_ts)")
            if not a["verified_by"]:
                miss.append("Verifier unavailable (no verified_by)")
            out.append(_mk(c, rule, a["machine_id"], rid, f"Action {rid} closed without required verification", sev,
                           f"Linked incident severity: {inc['severity'] if inc else 'unavailable'}.", w0, w1,
                           [f["reason"]], "The hazard addressed by this action must not be treated as resolved until verification is recorded (policy interpretation).",
                           dict(), evidence, miss, []))
        elif rule == "R-IN-01":
            i = c.inc[rid]
            sev = "HIGH" if i["severity"] in ("MAJOR", "CRITICAL") else "MEDIUM"
            t = parse_ts(i["opened_ts"])
            evidence = [dict(record_type="INCIDENT", record_id=rid, ts=i["opened_ts"], role="TRIGGER",
                             summary=f"{i['incident_type']} [{i['severity']}] machine_state_at_incident={i['machine_state_at_incident'] or 'EVIDENCE UNAVAILABLE'}")]
            miss = []
            if i["trigger_alarm_event_id"] in c.ev:
                evidence.append(_ev_entry(c, c.ev[i["trigger_alarm_event_id"]], "RELATED_ALARM"))
            elif not i["trigger_alarm_event_id"]:
                miss.append("Triggering alarm event: Evidence unavailable")
            if not i["machine_state_at_incident"]:
                miss.append("Machine state at incident: Evidence unavailable")
            for a in c.act_by_inc.get(rid, []):
                evidence.append(dict(record_type="CORRECTIVE_ACTION", record_id=a["action_id"], ts=a["opened_ts"], role="RELATED_ACTION",
                                     summary=f"{a['action_type']} status={a['status']}"))
            out.append(_mk(c, rule, i["machine_id"], rid, f"Incident {rid} lacks triggering evidence", sev, f"Incident severity {i['severity']}.", t, t,
                           [f["reason"]], "Cause analysis for this incident is limited by the missing evidence.", dict(), evidence, miss, []))
        elif rule == "R-TL-01":
            a = next(x for x in T["acknowledgements"] if x["ack_id"] == rid)
            e = c.ev.get(a["alarm_event_id"])
            if not e:
                continue
            t0, t1 = parse_ts(a["ack_ts"]), parse_ts(e["event_ts"])
            evidence = [_ev_entry(c, e, "TRIGGER"),
                        dict(record_type="ACKNOWLEDGEMENT", record_id=rid, ts=a["ack_ts"], role="CONTRADICTORY_RECORD", summary=f["reason"])]
            out.append(_mk(c, rule, e["machine_id"], rid, f"Acknowledgement {rid} precedes alarm {e['alarm_event_id']}", "LOW", "Data-integrity issue only.", t0, t1,
                           [f["reason"]], "Likely clock skew or a mis-keyed record (interpretation); the acknowledgement is excluded from response-time statistics.",
                           dict(), evidence, [], [f["reason"]]))
        elif rule == "R-ST-01":
            e = c.ev.get(rid)
            if not e:
                continue
            sev = "HIGH" if c.sev(e) == "CRITICAL" else "MEDIUM"
            t = e["_t"] if "_t" in e else parse_ts(e["event_ts"])
            ack_e, ack_missing = _ack_entries(c, [rid])
            evidence = [_ev_entry(c, e, "TRIGGER")] + ack_e + _context(c, e["machine_id"], t, t, {rid})
            out.append(_mk(c, rule, e["machine_id"], rid, f"Contradictory interlock data on {rid}", sev, f"Alarm severity {c.sev(e)}.", t, t,
                           [f["reason"]], "Either the interlock signal or the alarm configuration is wrong; neither has been verified.", dict(), evidence,
                           _event_missing(c, [rid], ack_missing)[0], [f["reason"]]))

    out.sort(key=lambda f: (f["rule_id"], f["machine_id"], f["window_start"], f["finding_id"]))
    ids = [f["finding_id"] for f in out]
    assert len(ids) == len(set(ids)), "finding IDs must be unique"
    return out

"""Rule-based detection. Works ONLY on the loaded data tables (never on ground-truth labels).

Anomaly rules (the five required edge cases):
  R-TL-01  acknowledgement earlier than its alarm            -> ACK_BEFORE_ALARM
  R-ST-01  impossible / contradictory interlock state        -> IMPOSSIBLE_INTERLOCK_STATE
  R-IN-01  incident without triggering alarm / state evidence -> INCIDENT_WITHOUT_TRIGGERING_CONTEXT
  R-DU-01  duplicate alarm replay                            -> DUPLICATE_ALARM_REPLAY
  R-LC-01  action closed without required verification       -> ACTION_CLOSED_WITHOUT_VERIFICATION

Operational rules (not anomalies, they describe safety performance):
  UNSAFE_CONDITION, DELAYED_ACK, UNACKNOWLEDGED, NUISANCE_CHATTER, ALARM_FLOOD, RECURRING_ALARM
"""
from __future__ import annotations

from collections import defaultdict
from datetime import timedelta

from . import config as C
from .exporters import parse_ts

RULE_TO_TYPE = {
    "R-TL-01": "ACK_BEFORE_ALARM",
    "R-ST-01": "IMPOSSIBLE_INTERLOCK_STATE",
    "R-IN-01": "INCIDENT_WITHOUT_TRIGGERING_CONTEXT",
    "R-DU-01": "DUPLICATE_ALARM_REPLAY",
    "R-LC-01": "ACTION_CLOSED_WITHOUT_VERIFICATION",
}

VALID_TRANSITIONS = {
    (None, "OPEN"), ("OPEN", "IN_PROGRESS"), ("IN_PROGRESS", "COMPLETED"),
    ("COMPLETED", "VERIFIED"), ("COMPLETED", "CLOSED"), ("VERIFIED", "CLOSED"),
}


def _finding(rule, table, rid, reason, related=""):
    return dict(rule_id=rule, anomaly_type=RULE_TO_TYPE[rule], table=table, record_id=rid,
                related_record_id=related or "", reason=reason)


def detect_anomalies(T):
    ev = {e["alarm_event_id"]: e for e in T["alarm_events"]}
    defs = {d["alarm_def_id"]: d for d in T["alarm_definitions"]}
    ils = {i["interlock_id"]: i for i in T["interlocks"]}
    out = []

    # R-TL-01 -- timeline violation
    for a in T["acknowledgements"]:
        e = ev.get(a["alarm_event_id"])
        if e and parse_ts(a["ack_ts"]) < parse_ts(e["event_ts"]):
            gap = int((parse_ts(e["event_ts"]) - parse_ts(a["ack_ts"])).total_seconds())
            out.append(_finding("R-TL-01", "acknowledgements", a["ack_id"],
                                f"ack_ts is {gap}s before the alarm's event_ts", a["alarm_event_id"]))

    # R-ST-01 -- invalid state combination
    for e in T["alarm_events"]:
        d = defs[e["alarm_def_id"]]
        why = []
        il = ils.get(e["interlock_id"]) if e["interlock_id"] else None
        if d["interlock_type"]:
            if il is None:
                why.append("interlock-based alarm has no interlock reference")
            else:
                if il["machine_id"] != e["machine_id"]:
                    why.append(f"interlock {il['interlock_id']} belongs to {il['machine_id']}, not {e['machine_id']}")
                if il["interlock_type"] != d["interlock_type"]:
                    why.append(f"interlock type {il['interlock_type']} != definition type {d['interlock_type']}")
            if e["interlock_state"] not in d["expected_interlock_states"].split("|"):
                why.append(f"interlock_state {e['interlock_state']} contradicts definition (expects {d['expected_interlock_states']})")
        else:
            if e["interlock_id"] or e["interlock_state"] != "NOT_APPLICABLE":
                why.append("non-interlock alarm carries interlock data")
        if e["interlock_state"] == "BYPASSED":
            allowed = (il["bypass_permitted_states"].split("|") if il else [])
            if e["machine_state"] not in allowed:
                why.append(f"interlock BYPASSED while machine {e['machine_state']} (permitted only in {'/'.join(allowed) or 'n/a'})")
        if why:
            out.append(_finding("R-ST-01", "alarm_events", e["alarm_event_id"], "; ".join(why)))

    # R-IN-01 -- missing evidence
    for i in T["incidents"]:
        why = []
        if i["trigger_alarm_event_id"] is None:
            why.append("no triggering alarm event")
        elif i["trigger_alarm_event_id"] in ev and ev[i["trigger_alarm_event_id"]]["machine_id"] != i["machine_id"]:
            why.append("triggering alarm belongs to a different machine")
        if i["machine_state_at_incident"] is None:
            why.append("no machine-state evidence")
        if why:
            out.append(_finding("R-IN-01", "incidents", i["incident_id"], "; ".join(why), i["trigger_alarm_event_id"]))

    # R-DU-01 -- replayed duplicates (flag every copy after the first-ingested one)
    groups = defaultdict(list)
    for e in T["alarm_events"]:
        groups[(e["machine_id"], e["alarm_def_id"], e["interlock_id"], e["event_ts"], e["machine_state"],
                e["interlock_state"])].append(e)
    for g in groups.values():
        if len(g) > 1:
            g.sort(key=lambda e: (e["ingested_ts"], e["alarm_event_id"]))
            for dup in g[1:]:
                out.append(_finding("R-DU-01", "alarm_events", dup["alarm_event_id"],
                                    f"identical content to {g[0]['alarm_event_id']} (batch {g[0]['ingest_batch_id']} vs {dup['ingest_batch_id']})",
                                    g[0]["alarm_event_id"]))

    # R-LC-01 -- lifecycle
    hist = defaultdict(list)
    for h in T["corrective_action_history"]:
        hist[h["action_id"]].append(h)
    for a in T["corrective_actions"]:
        why = []
        hs = sorted(hist[a["action_id"]], key=lambda h: h["seq"])
        for h in hs:
            pair = (h["from_status"], h["to_status"])
            if pair not in VALID_TRANSITIONS:
                why.append(f"invalid transition {pair[0]}->{pair[1]}")
            elif pair == ("COMPLETED", "CLOSED") and a["verification_required"] == 1:
                why.append("COMPLETED->CLOSED skips VERIFIED although verification is required")
        if a["status"] == "CLOSED" and a["verification_required"] == 1 and (a["verified_ts"] is None or a["verified_by"] is None):
            why.append("CLOSED without verified_ts/verified_by")
        if a["verified_ts"] and a["completed_ts"] and parse_ts(a["verified_ts"]) < parse_ts(a["completed_ts"]):
            why.append("verified before work completed")
        if why:
            out.append(_finding("R-LC-01", "corrective_actions", a["action_id"], "; ".join(dict.fromkeys(why)), a["incident_id"]))
    return out


def classify_operations(T, anomalies, as_of=None):
    """Per-event classification (SAFE / UNSAFE / DELAYED / SUSPICIOUS / DUPLICATE) plus flood/recurring episodes."""
    R = C.RULES
    defs = {d["alarm_def_id"]: d for d in T["alarm_definitions"]}
    dup_ids = {f["record_id"] for f in anomalies if f["rule_id"] == "R-DU-01"}
    susp_ids = {f["record_id"] for f in anomalies if f["rule_id"] == "R-ST-01"}
    acks = {}
    bad_ack = {f["record_id"] for f in anomalies if f["rule_id"] == "R-TL-01"}
    for a in T["acknowledgements"]:
        if a["ack_id"] not in bad_ack:   # invalid acks are excluded from response-time statistics
            acks[a["alarm_event_id"]] = a
    events = [e for e in T["alarm_events"] if e["alarm_event_id"] not in dup_ids]
    for e in events:
        e["_t"] = parse_ts(e["event_ts"])
    if as_of is None and events:
        as_of = max(e["_t"] for e in events)
    grace = timedelta(seconds=R["unack_grace_s"])
    flags = defaultdict(set)

    for e in events:
        d = defs[e["alarm_def_id"]]
        eid = e["alarm_event_id"]
        if e["machine_state"] == "RUNNING" and e["interlock_state"] == "DISENGAGED":
            flags[eid].add("UNSAFE_CONDITION")
        a = acks.get(eid)
        if a:
            resp = (parse_ts(a["ack_ts"]) - e["_t"]).total_seconds()
            if resp > d["ack_sla_seconds"]:
                flags[eid].add("DELAYED_ACK")
        elif d["severity"] in ("HIGH", "CRITICAL") and e["_t"] + grace <= as_of:
            flags[eid].add("UNACKNOWLEDGED")   # younger than the grace period at the end of the data: not yet overdue
        if eid in susp_ids:
            flags[eid].add("SUSPICIOUS")

    # nuisance chatter: >=3 repeats of the same LOW/MEDIUM alarm on a machine inside 10 minutes
    by_md = defaultdict(list)
    for e in events:
        by_md[(e["machine_id"], e["alarm_def_id"])].append(e)
    win = timedelta(seconds=R["chatter_window_s"])
    for (m, dd), lst in by_md.items():
        if not defs[dd]["nuisance_candidate"]:
            continue
        lst.sort(key=lambda e: e["_t"])
        k = 0
        for j in range(len(lst)):
            k = max(k, j)
            while k + 1 < len(lst) and lst[k + 1]["_t"] - lst[j]["_t"] <= win:
                k += 1
            if k - j + 1 >= R["chatter_min_repeats"]:
                for x in range(j, k + 1):
                    flags[lst[x]["alarm_event_id"]].add("NUISANCE_CHATTER")

    # alarm floods: >=10 alarms on one machine in 10 minutes (merged into episodes)
    floods = []
    by_m = defaultdict(list)
    for e in events:
        by_m[e["machine_id"]].append(e)
    fwin = timedelta(seconds=R["flood_window_s"])
    for m, lst in by_m.items():
        lst.sort(key=lambda e: e["_t"])
        k, cur = 0, None
        for j in range(len(lst)):
            k = max(k, j)
            while k + 1 < len(lst) and lst[k + 1]["_t"] - lst[j]["_t"] <= fwin:
                k += 1
            if k - j + 1 >= R["flood_min_alarms"]:
                s, t_end = lst[j]["_t"], lst[k]["_t"]
                if cur and s <= cur["end"]:
                    cur["end"] = max(cur["end"], t_end)
                    cur["ids"].update(x["alarm_event_id"] for x in lst[j:k + 1])
                else:
                    if cur:
                        floods.append(cur)
                    cur = dict(machine_id=m, start=s, end=t_end, ids={x["alarm_event_id"] for x in lst[j:k + 1]})
        if cur:
            floods.append(cur)
    for f in floods:
        for i in f["ids"]:
            flags[i].add("ALARM_FLOOD")

    # recurring HIGH/CRITICAL alarms: >=5 of same alarm on a machine in 7 days
    rwin = timedelta(days=R["recurring_window_days"])
    recurring = []
    for (m, dd), lst in by_md.items():
        if defs[dd]["severity"] not in ("HIGH", "CRITICAL"):
            continue
        lst.sort(key=lambda e: e["_t"])
        k = 0
        marked = set()
        for j in range(len(lst)):
            k = max(k, j)
            while k + 1 < len(lst) and lst[k + 1]["_t"] - lst[j]["_t"] <= rwin:
                k += 1
            if k - j + 1 >= R["recurring_min_events"]:
                marked.update(range(j, k + 1))
        if marked:
            recurring.append(dict(machine_id=m, alarm_def_id=dd, events=len(marked), total=len(lst)))
            for x in marked:
                flags[lst[x]["alarm_event_id"]].add("RECURRING_ALARM")

    # recurring unsafe conditions per machine: >=3 UNSAFE events in 7 days
    uwin = timedelta(days=R["recurring_unsafe_window_days"])
    rec_unsafe = {}
    for m, lst in by_m.items():
        un = [e for e in lst if "UNSAFE_CONDITION" in flags[e["alarm_event_id"]]]
        k, best = 0, 0
        for j in range(len(un)):
            k = max(k, j)
            while k + 1 < len(un) and un[k + 1]["_t"] - un[j]["_t"] <= uwin:
                k += 1
            best = max(best, k - j + 1)
        rec_unsafe[m] = dict(unsafe_total=len(un), max_unsafe_in_window=best, recurring=best >= R["recurring_unsafe_min_events"])

    classification = []
    for e in T["alarm_events"]:
        eid = e["alarm_event_id"]
        if eid in dup_ids:
            cls, fl = "DUPLICATE", ["DUPLICATE_REPLAY"]
        else:
            fl = sorted(flags[eid])
            cls = ("SUSPICIOUS" if "SUSPICIOUS" in fl else "UNSAFE" if "UNSAFE_CONDITION" in fl
                   else "DELAYED" if ("DELAYED_ACK" in fl or "UNACKNOWLEDGED" in fl) else "SAFE")
        classification.append(dict(alarm_event_id=eid, machine_id=e["machine_id"], alarm_def_id=e["alarm_def_id"],
                                   classification=cls, flags="|".join(fl)))
    return dict(classification=classification, flags=flags, floods=floods, recurring=recurring,
                rec_unsafe=rec_unsafe, events=events, acks=acks, defs=defs)

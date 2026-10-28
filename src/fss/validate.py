"""Validation: structural integrity (must PASS) and semantic checks (violations are reported as findings)."""
from __future__ import annotations

from collections import Counter, defaultdict

from .exporters import parse_ts
from .schema import TABLES, CREATE_ORDER


def validate(T, profile=None):
    checks = []

    def add(group, name, bad, total, kind="structural", note=""):
        status = "PASS" if bad == 0 else ("FAIL" if kind == "structural" else "FINDINGS")
        checks.append(dict(group=group, check=name, checked=total, violations=bad, status=status, kind=kind, note=note))

    # ---- structural: PK / NOT NULL / enum / FK
    for name in CREATE_ORDER:
        t, rows = TABLES[name], T[name]
        ids = [r[t.pk] for r in rows]
        dupes = sum(c - 1 for c in Counter(ids).values() if c > 1) + sum(1 for i in ids if i is None)
        add("primary_key", f"{name}.{t.pk} unique & not null", dupes, len(rows))
        nn = sum(1 for r in rows for c in t.cols if not c.nullable and r[c.name] is None)
        add("not_null", f"{name} required columns populated", nn, len(rows) * len(t.cols))
        for c in t.cols:
            if c.allowed:
                bad = sum(1 for r in rows if r[c.name] is not None and str(r[c.name]) not in c.allowed)
                add("enumeration", f"{name}.{c.name} in allowed set", bad, len(rows))
            if c.fk:
                rt, rc = c.fk.split(".")
                keys = {r[rc] for r in T[rt]}
                bad = sum(1 for r in rows if r[c.name] is not None and r[c.name] not in keys)
                add("foreign_key", f"{name}.{c.name} -> {c.fk}", bad, sum(1 for r in rows if r[c.name] is not None))

    # ---- structural: cross-table consistency & timelines that must always hold
    mach = {m["machine_id"]: m for m in T["machines"]}
    zone = {z["zone_id"]: z for z in T["safety_zones"]}
    add("consistency", "machine.zone belongs to machine.plant",
        sum(1 for m in T["machines"] if zone[m["zone_id"]]["plant_id"] != m["plant_id"]), len(T["machines"]))
    add("consistency", "alarm_event.zone_id equals machine.zone_id",
        sum(1 for e in T["alarm_events"] if mach[e["machine_id"]]["zone_id"] != e["zone_id"]), len(T["alarm_events"]))
    dmt = {d["alarm_def_id"]: d["applicable_machine_type"] for d in T["alarm_definitions"]}
    add("consistency", "alarm definition applies to the machine's type",
        sum(1 for e in T["alarm_events"] if dmt[e["alarm_def_id"]] != mach[e["machine_id"]]["machine_type"]), len(T["alarm_events"]))
    add("timeline", "alarm_events.clear_ts >= event_ts",
        sum(1 for e in T["alarm_events"] if e["clear_ts"] and parse_ts(e["clear_ts"]) < parse_ts(e["event_ts"])), len(T["alarm_events"]))
    add("timeline", "alarm_events.ingested_ts >= event_ts",
        sum(1 for e in T["alarm_events"] if parse_ts(e["ingested_ts"]) < parse_ts(e["event_ts"])), len(T["alarm_events"]))
    add("timeline", "operator_shifts.shift_end > shift_start",
        sum(1 for s in T["operator_shifts"] if parse_ts(s["shift_end"]) <= parse_ts(s["shift_start"])), len(T["operator_shifts"]))
    ev = {e["alarm_event_id"]: e for e in T["alarm_events"]}
    add("timeline", "incident.opened_ts >= trigger alarm event_ts",
        sum(1 for i in T["incidents"] if i["trigger_alarm_event_id"] in ev
            and parse_ts(i["opened_ts"]) < parse_ts(ev[i["trigger_alarm_event_id"]]["event_ts"])),
        sum(1 for i in T["incidents"] if i["trigger_alarm_event_id"]))
    chain_bad = 0
    for a in T["corrective_actions"]:
        seq = [parse_ts(a[k]) for k in ("opened_ts", "completed_ts", "verified_ts", "closed_ts") if a[k]]
        chain_bad += seq != sorted(seq)
    add("timeline", "corrective action timestamps are monotonic", chain_bad, len(T["corrective_actions"]))
    hist = defaultdict(list)
    for h in T["corrective_action_history"]:
        hist[h["action_id"]].append(h["seq"])
    add("history", "history seq is contiguous 1..n per action",
        sum(1 for s in hist.values() if sorted(s) != list(range(1, len(s) + 1))), len(hist))
    st = {a["action_id"]: a["status"] for a in T["corrective_actions"]}
    last = {}
    for h in sorted(T["corrective_action_history"], key=lambda h: (h["action_id"], h["seq"])):
        last[h["action_id"]] = h["to_status"]
    add("history", "latest history status equals corrective_actions.status",
        sum(1 for k, v in st.items() if last.get(k) != v), len(st))

    # ---- semantic: the five edge-case rules -> reported as findings (expected to be non-zero in test data)
    ack_bad = sum(1 for a in T["acknowledgements"] if a["alarm_event_id"] in ev
                  and parse_ts(a["ack_ts"]) < parse_ts(ev[a["alarm_event_id"]]["event_ts"]))
    add("semantic", "acknowledgement not earlier than alarm (R-TL-01)", ack_bad, len(T["acknowledgements"]), "semantic")
    keys = Counter((e["machine_id"], e["alarm_def_id"], e["interlock_id"], e["event_ts"], e["machine_state"], e["interlock_state"])
                   for e in T["alarm_events"])
    add("semantic", "no duplicate alarm content (R-DU-01)", sum(c - 1 for c in keys.values() if c > 1), len(T["alarm_events"]), "semantic")
    add("semantic", "incident has trigger alarm and machine state (R-IN-01)",
        sum(1 for i in T["incidents"] if i["trigger_alarm_event_id"] is None or i["machine_state_at_incident"] is None),
        len(T["incidents"]), "semantic")
    add("semantic", "closed actions needing verification are verified (R-LC-01)",
        sum(1 for a in T["corrective_actions"] if a["status"] == "CLOSED" and a["verification_required"] == 1 and not a["verified_ts"]),
        sum(1 for a in T["corrective_actions"] if a["status"] == "CLOSED" and a["verification_required"] == 1), "semantic")

    # ---- scale check
    if profile is not None:
        scale = [("plants", len(T["plants"]), profile.n_plants), ("machines", len(T["machines"]), profile.n_machines),
                 ("alarm_definitions", len(T["alarm_definitions"]), profile.n_alarm_defs),
                 ("alarm_events", len(T["alarm_events"]), profile.n_events)]
        for n, got, want in scale:
            add("scale", f"{n} count == {want}", 0 if got == want else 1, 1, note=f"got {got}")
    return checks


def report_md(checks, title="Validation Report"):
    fails = [c for c in checks if c["status"] == "FAIL"]
    L = [f"# {title}", "",
         f"**Structural integrity: {'PASS' if not fails else 'FAIL'}** "
         f"({sum(1 for c in checks if c['kind'] == 'structural' and c['status'] == 'PASS')} of "
         f"{sum(1 for c in checks if c['kind'] == 'structural')} structural checks passed).", "",
         "*Semantic* checks list business-rule violations; non-zero counts are expected because test anomalies are injected "
         "on purpose. They are reconciled against the separate ground truth in the evaluation report.", ""]
    for kind in ("structural", "semantic"):
        L += [f"## {kind.capitalize()} checks", "", "| Group | Check | Checked | Violations | Status |", "|---|---|---:|---:|---|"]
        for c in checks:
            if c["kind"] == kind:
                L.append(f"| {c['group']} | {c['check']}{' (' + c['note'] + ')' if c['note'] else ''} | {c['checked']} | {c['violations']} | {c['status']} |")
        L.append("")
    return "\n".join(L)

"""Deterministic synthetic data generator.

Everything is driven by one ``random.Random(seed)`` and a fixed base date, so the
same (profile, seed) always yields byte-identical output.

The generator also injects the five required edge cases and writes the labels to a
*separate* ground-truth structure. The detection code never sees those labels.
"""
from __future__ import annotations

import hashlib
import math
import random
from datetime import date, timedelta

from . import config as C
from .schema import TABLES, GROUND_TRUTH_COLUMNS, CONTROL_COLUMNS

HOUR_W = [1, 1, 1, 1, 1, 2, 4, 5, 6, 6, 6, 5, 4, 5, 6, 6, 6, 5, 4, 3, 2, 2, 1, 1]
SEV_DEF_WEIGHT = {"CRITICAL": 0.25, "HIGH": 0.6, "MEDIUM": 1.0, "LOW": 1.2}
STATES = ["RUNNING", "IDLE", "STOPPED", "FAULT", "SETUP", "MAINTENANCE"]
STATE_W_INTERLOCK = [12, 25, 20, 13, 15, 15]
STATE_W_OTHER = [65, 10, 5, 10, 5, 5]


def fmt(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def content_hash(machine_id, def_id, interlock_id, event_ts, machine_state, interlock_state):
    raw = "|".join([machine_id, def_id, interlock_id or "", event_ts, machine_state, interlock_state])
    return hashlib.sha256(raw.encode()).hexdigest()


def generate(profile: C.Profile, seed: int = C.DEFAULT_SEED):
    """Return (tables, ground_truth_rows, control_rows, meta)."""
    rng = random.Random(seed)
    p = profile
    shift_base = C.BASE_DATE + timedelta(hours=0, minutes=30)  # 06:00 IST == 00:30 UTC
    as_of = shift_base + timedelta(days=p.days)

    # ------------------------------------------------------------------ master data
    plants = [dict(plant_id=pid, plant_name=name, city=city, country="India", timezone="Asia/Kolkata")
              for pid, name, city in C.PLANTS[:p.n_plants]]

    zones, zones_by_plant = [], {}
    zn = 0
    for pl in plants:
        for j in range(p.zones_per_plant):
            zn += 1
            ztype = C.ZONE_TYPES[j % len(C.ZONE_TYPES)]
            z = dict(zone_id=f"Z{zn:02d}", plant_id=pl["plant_id"], zone_name=f"{pl['city']} {ztype.title().replace('_', ' ')} {j + 1}",
                     zone_type=ztype, risk_level=C.ZONE_RISK[ztype])
            zones.append(z)
            zones_by_plant.setdefault(pl["plant_id"], []).append(z)

    machines = []
    per_plant = p.n_machines // p.n_plants
    mn = 0
    for pl in plants:
        for _ in range(per_plant):
            mtype = C.MACHINE_TYPES[mn % p.n_machine_types]
            z = rng.choice(zones_by_plant[pl["plant_id"]])
            machines.append(dict(
                machine_id=f"M{mn + 1:03d}", plant_id=pl["plant_id"], zone_id=z["zone_id"],
                machine_name=f"{mtype.replace('_', ' ').title()} {mn + 1:02d}", machine_type=mtype,
                criticality=C.MACHINE_CRITICALITY[mtype],
                install_date=str(date(rng.randint(2012, 2024), rng.randint(1, 12), rng.randint(1, 28))),
                status="ACTIVE"))
            mn += 1
    mach = {m["machine_id"]: m for m in machines}

    interlocks, il_by_machine = [], {}
    iln = 0
    for m in machines:
        types = ["GUARD_DOOR", "E_STOP"] + [t for t in C.OPTIONAL_INTERLOCKS if rng.random() < 0.6]
        for t in types:
            iln += 1
            il = dict(interlock_id=f"IL{iln:04d}", machine_id=m["machine_id"], zone_id=m["zone_id"], interlock_type=t,
                      tag_name=f"{m['machine_id']}.SAF.{t}", safety_rating=rng.choice(["PLc", "PLd", "PLe"]),
                      bypass_permitted_states="MAINTENANCE|SETUP", status="ACTIVE")
            interlocks.append(il)
            il_by_machine.setdefault(m["machine_id"], {})[t] = il

    alarm_defs, defs_by_type = [], {}
    dn = 0
    for mtype in C.MACHINE_TYPES[:p.n_machine_types]:
        for code, name, cat, sev, itype, exp, req in C.ALARM_TEMPLATES[:p.templates_per_type]:
            dn += 1
            d = dict(alarm_def_id=f"AD-{dn:03d}", alarm_code=f"{code}.{mtype}", alarm_name=f"{name} ({mtype.replace('_', ' ').title()})",
                     category=cat, severity=sev, applicable_machine_type=mtype, interlock_type=itype,
                     expected_interlock_states=exp, ack_sla_seconds=C.ACK_SLA_SECONDS[sev],
                     requires_incident=req, nuisance_candidate=1 if sev in ("LOW", "MEDIUM") else 0, is_active=1,
                     description=f"{name} on {mtype.replace('_', ' ').lower()} equipment; severity {sev}.")
            alarm_defs.append(d)
            defs_by_type.setdefault(mtype, []).append(d)
    defs = {d["alarm_def_id"]: d for d in alarm_defs}

    # ------------------------------------------------------------------ operator shifts
    pools = {}
    for pl in plants:
        pools[pl["plant_id"]] = [
            (f"OP-{pl['plant_id']}-{i + 1:03d}",
             f"{C.FIRST_NAMES[(i * 7 + len(pl['plant_id'])) % len(C.FIRST_NAMES)]} {C.LAST_NAMES[(i * 5 + 3) % len(C.LAST_NAMES)]}")
            for i in range(max(24, p.zones_per_plant * 2))]
    shifts, shift_idx = [], {}
    sn = 0
    for pl in plants:
        pz = zones_by_plant[pl["plant_id"]]
        for day in range(p.days):
            for si, (sname, off) in enumerate(C.SHIFTS):
                crew = rng.sample(pools[pl["plant_id"]], len(pz))
                start = shift_base + timedelta(days=day, hours=off)
                for z, (opid, opname) in zip(pz, crew):
                    sn += 1
                    row = dict(shift_id=f"SH-{sn:06d}", plant_id=pl["plant_id"], zone_id=z["zone_id"], operator_id=opid,
                               operator_name=opname, shift_name=sname, shift_start=fmt(start),
                               shift_end=fmt(start + timedelta(hours=8)))
                    shifts.append(row)
                    shift_idx.setdefault((pl["plant_id"], z["zone_id"]), []).append(row)

    def shift_for(machine, t):
        lst = shift_idx[(machine["plant_id"], machine["zone_id"])]
        k = int((t - shift_base).total_seconds() // 28800)
        return lst[max(0, min(k, len(lst) - 1))]

    # ------------------------------------------------------------------ machine alarm profiles
    chronic = set(m["machine_id"] for m in rng.sample(machines, p.n_chronic_machines))
    info = {}
    for m in machines:
        has = il_by_machine[m["machine_id"]]
        elig = [d for d in defs_by_type[m["machine_type"]] if d["interlock_type"] is None or d["interlock_type"] in has]
        order = elig[:]
        rng.shuffle(order)
        w = [SEV_DEF_WEIGHT[d["severity"]] / ((r + 1) ** 0.9) for r, d in enumerate(order)]
        if m["machine_id"] in chronic:  # a few chronic problem alarms on problem machines
            hot = [i for i, d in enumerate(order) if d["interlock_type"] == "GUARD_DOOR" and d["alarm_code"].startswith("GUARD")]
            hot += rng.sample(range(len(order)), 2)
            for i in hot:
                w[i] *= 10
        info[m["machine_id"]] = dict(has=has, defs=order, w=w)
    m_weights = [(6.0 if m["machine_id"] in chronic else 1.0) * rng.uniform(0.6, 1.4) for m in machines]

    # ------------------------------------------------------------------ alarm events
    events, used, counter = [], set(), [0]
    hw = [HOUR_W[(h + 5) % 24] for h in range(24)]

    def rand_time():
        while True:
            t = shift_base + timedelta(days=rng.randrange(p.days), hours=rng.choices(range(24), hw)[0],
                                       seconds=rng.randrange(3600))
            if t < as_of - timedelta(hours=3):
                return t

    def mk(m, d, t, kind, short=False):
        key = (m["machine_id"], d["alarm_def_id"], t)
        if key in used:
            return None
        used.add(key)
        il = info[m["machine_id"]]["has"].get(d["interlock_type"]) if d["interlock_type"] else None
        istate = rng.choice(d["expected_interlock_states"].split("|")) if il else "NOT_APPLICABLE"
        mstate = rng.choices(STATES, STATE_W_INTERLOCK if il else STATE_W_OTHER)[0]
        dur = rng.randint(3, 40) if short else max(2, int(rng.lognormvariate(math.log(C.DURATION_MEDIAN_SECONDS[d["severity"]]), 0.8)))
        clear = fmt(t + timedelta(seconds=dur)) if rng.random() > 0.02 else None
        counter[0] += 1
        ing = t + timedelta(seconds=rng.randint(1, 8))
        ev = dict(_i=counter[0], _kind=kind, _t=t, _imp=False, alarm_event_id=None, alarm_def_id=d["alarm_def_id"],
                  machine_id=m["machine_id"], zone_id=m["zone_id"], interlock_id=il["interlock_id"] if il else None,
                  event_ts=fmt(t), clear_ts=clear, machine_state=mstate, interlock_state=istate,
                  source_system=rng.choices(["PLC_SCADA", "EDGE_GATEWAY", "HISTORIAN"], [70, 25, 5])[0],
                  ingest_batch_id=f"BATCH-{ing:%Y%m%d}", ingested_ts=fmt(ing), content_hash=None)
        events.append(ev)
        return ev

    def pick_machine():
        return rng.choices(machines, m_weights)[0]

    n_dups = p.inj_duplicate_replay
    n_base = p.n_events - n_dups
    # chatter bursts: LOW/MEDIUM alarm repeating every 15-70 s
    for _ in range(p.n_chatter_bursts):
        for _try in range(20):
            m = pick_machine()
            cand = [d for d in info[m["machine_id"]]["defs"] if d["nuisance_candidate"]]
            if cand:
                break
        d = rng.choice(cand)
        t = rand_time()
        for _ in range(rng.randint(3, 8)):
            mk(m, d, t, "chatter", short=True)
            t += timedelta(seconds=rng.randint(15, 70))
    # alarm floods: 12-35 mixed alarms on one machine within 8 minutes
    for _ in range(p.n_floods):
        m = pick_machine()
        t0 = rand_time()
        for _ in range(rng.randint(12, 35)):
            d = rng.choice(info[m["machine_id"]]["defs"])
            mk(m, d, t0 + timedelta(seconds=rng.randint(0, 480)), "flood")
    # singles
    target_singles = n_base - p.n_twins
    while len(events) < target_singles:
        m = pick_machine()
        d = rng.choices(info[m["machine_id"]]["defs"], info[m["machine_id"]]["w"])[0]
        mk(m, d, rand_time(), "single")
    singles = [e for e in events if e["_kind"] == "single"]
    # twins: legitimate repeats 1-2 s apart (hard negatives for the duplicate detector)
    twins = []
    for src in rng.sample(singles, p.n_twins):
        for _try in range(10):
            tw = mk(mach[src["machine_id"]], defs[src["alarm_def_id"]], src["_t"] + timedelta(seconds=rng.randint(1, 2)), "twin")
            if tw:
                twins.append((tw, src))
                break
    while len(events) < n_base:  # top-up if a twin collided
        m = pick_machine()
        mk(m, rng.choices(info[m["machine_id"]]["defs"], info[m["machine_id"]]["w"])[0], rand_time(), "single")

    # ---- injection: impossible interlock state (edge case 2)
    gt, controls = [], []
    cand = [e for e in events if e["_kind"] in ("single", "flood", "chatter")
            and defs[e["alarm_def_id"]]["interlock_type"] and defs[e["alarm_def_id"]]["expected_interlock_states"] == "DISENGAGED"]
    chosen = rng.sample(cand, min(p.inj_impossible_state, len(cand)))
    variants = ["STATE_CONTRADICTS_DEFINITION", "BYPASSED_WHILE_RUNNING", "INTERLOCK_OF_OTHER_MACHINE"]
    imp_meta = {}
    for k, e in enumerate(chosen):
        v = variants[k % 3]
        e["_imp"] = True
        if v == "STATE_CONTRADICTS_DEFINITION":
            e["interlock_state"] = "ENGAGED"
            why = "Alarm definition requires interlock DISENGAGED but the record says ENGAGED."
        elif v == "BYPASSED_WHILE_RUNNING":
            e["interlock_state"], e["machine_state"] = "BYPASSED", "RUNNING"
            why = "Interlock BYPASSED while machine RUNNING; bypass is only permitted in MAINTENANCE/SETUP."
        else:
            d = defs[e["alarm_def_id"]]
            others = [il for il in interlocks if il["interlock_type"] == d["interlock_type"] and il["machine_id"] != e["machine_id"]]
            e["interlock_id"] = rng.choice(others)["interlock_id"]
            why = "Event references an interlock that belongs to a different machine."
        imp_meta[e["_i"]] = (v, why)

    # ---- injection: duplicate replay (edge case 4)
    pool = [e for e in events if e["_kind"] in ("single", "chatter", "flood") and not e["_imp"]]
    n_src = math.ceil(n_dups * 0.9)
    sources = rng.sample(pool, n_src)
    srcs = sources + [rng.choice(sources) for _ in range(n_dups - n_src)]
    replays = []
    for src in srcs:
        counter[0] += 1
        ing = _parse(src["ingested_ts"]) + timedelta(seconds=rng.randint(3600, 3 * 86400))
        rp = dict(src)
        rp.update(_i=counter[0], _kind="replay", _src=src, alarm_event_id=None,
                  ingest_batch_id=f"REPLAY-{ing:%Y%m%d}", ingested_ts=fmt(ing))
        replays.append(rp)
    events.extend(replays)

    for e in events:
        e["content_hash"] = content_hash(e["machine_id"], e["alarm_def_id"], e["interlock_id"], e["event_ts"],
                                         e["machine_state"], e["interlock_state"])
    events.sort(key=lambda e: (e["ingested_ts"], e["_i"]))
    for n, e in enumerate(events, 1):
        e["alarm_event_id"] = f"AE-{n:06d}"
    ev_by_id = {e["alarm_event_id"]: e for e in events}
    assert len(events) == p.n_events, (len(events), p.n_events)

    # ground truth: impossible + duplicates
    an = [0]

    def add_gt(edge, atype, table, rid, rel, variant, why, rule):
        an[0] += 1
        gt.append(dict(anomaly_id=f"GT-{an[0]:04d}", edge_case_no=edge, anomaly_type=atype, table=table, record_id=rid,
                       related_record_id=rel or "", variant=variant, why_anomalous=why, expected_rule=rule,
                       expected_decision="FLAG"))

    for e in events:
        if e["_imp"]:
            v, why = imp_meta[e["_i"]]
            add_gt(2, "IMPOSSIBLE_INTERLOCK_STATE", "alarm_events", e["alarm_event_id"], "", v, why, "R-ST-01")
        if e["_kind"] == "replay":
            add_gt(4, "DUPLICATE_ALARM_REPLAY", "alarm_events", e["alarm_event_id"], e["_src"]["alarm_event_id"], "REPLAY_COPY",
                   "Re-delivered copy of an earlier alarm event (identical business content, later ingestion batch).", "R-DU-01")
    for tw, src in twins:
        controls.append(dict(control_type="NEAR_DUPLICATE_DIFFERENT_SECOND", table="alarm_events", record_id=tw["alarm_event_id"],
                             why_normal=f"Same alarm as {src['alarm_event_id']} but raised {int((tw['_t'] - src['_t']).total_seconds())}s later: a genuine repeat, not a replay.",
                             expected_decision="NOT_FLAGGED"))

    # ------------------------------------------------------------------ acknowledgements
    meth_w = ["HMI", "RADIO", "PHONE", "MOBILE_APP"], [70, 15, 5, 10]
    acks = []
    for e in events:
        if e["_kind"] == "replay":
            continue
        d = defs[e["alarm_def_id"]]
        if rng.random() > C.ACK_PROBABILITY[d["severity"]]:
            continue
        m = mach[e["machine_id"]]
        resp = max(1, int(rng.lognormvariate(math.log(C.ACK_MEDIAN_SECONDS[d["severity"]]), 0.7)))
        if rng.random() < 0.07:
            resp *= rng.randint(4, 10)
        sh = shift_for(m, e["_t"])
        acks.append(dict(ack_id=f"AK-{len(acks) + 1:06d}", alarm_event_id=e["alarm_event_id"], operator_id=sh["operator_id"],
                         shift_id=sh["shift_id"], ack_ts=fmt(e["_t"] + timedelta(seconds=resp)),
                         ack_method=rng.choices(*meth_w)[0],
                         comment=rng.choice([None, None, None, "Operator informed maintenance", "Area checked", "Reset after inspection"])))
    ack_pick = rng.sample(range(len(acks)), p.inj_ack_before_alarm + p.ctl_zero_second_ack)
    for ix in ack_pick[:p.ctl_zero_second_ack]:     # hard negatives: ack in the same second as alarm
        a = acks[ix]
        a["ack_ts"] = ev_by_id[a["alarm_event_id"]]["event_ts"]
        controls.append(dict(control_type="ACK_SAME_SECOND_AS_ALARM", table="acknowledgements", record_id=a["ack_id"],
                             why_normal="Acknowledgement time equals alarm time (0 s response); not earlier than the alarm.",
                             expected_decision="NOT_FLAGGED"))
    for ix in ack_pick[p.ctl_zero_second_ack:]:     # edge case 1
        a = acks[ix]
        ev = ev_by_id[a["alarm_event_id"]]
        delta = rng.randint(5, 900)
        a["ack_ts"] = fmt(ev["_t"] - timedelta(seconds=delta))
        add_gt(1, "ACK_BEFORE_ALARM", "acknowledgements", a["ack_id"], a["alarm_event_id"], f"ACK_{delta}S_EARLY",
               f"Acknowledgement is {delta}s earlier than the alarm it acknowledges.", "R-TL-01")

    # ------------------------------------------------------------------ incidents
    incidents, last_inc = [], {}
    for e in sorted((x for x in events if x["_kind"] != "replay" and not x["_imp"]), key=lambda x: x["_t"]):
        d = defs[e["alarm_def_id"]]
        unsafe = e["machine_state"] == "RUNNING" and e["interlock_state"] == "DISENGAGED"
        if not (unsafe or (d["requires_incident"] and e["machine_state"] == "RUNNING")):
            continue
        if e["machine_id"] in last_inc and e["_t"] - last_inc[e["machine_id"]] < timedelta(hours=12):
            continue
        if rng.random() > 0.5:
            continue
        last_inc[e["machine_id"]] = e["_t"]
        m = mach[e["machine_id"]]
        running = e["machine_state"] == "RUNNING"
        sev = "CRITICAL" if d["severity"] == "CRITICAL" and running else ("MAJOR" if unsafe or d["severity"] == "CRITICAL" else "MODERATE")
        code = d["alarm_code"].split(".")[0]
        opened = e["_t"] + timedelta(seconds=rng.randint(60, 900))
        incidents.append(dict(
            incident_id=f"INC-{len(incidents) + 1:05d}", machine_id=m["machine_id"], zone_id=m["zone_id"],
            trigger_alarm_event_id=e["alarm_event_id"], machine_state_at_incident=e["machine_state"],
            incident_type=code + ("_WHILE_RUNNING" if running else ""), severity=sev, opened_ts=fmt(opened),
            closed_ts=None, status="OPEN",
            description=f"{d['alarm_name']} on {m['machine_name']}; machine state {e['machine_state']}, interlock {e['interlock_state']}.",
            _opened=opened, _plant=m["plant_id"], _cat=d["category"]))

    # ------------------------------------------------------------------ corrective actions
    actions, trans = [], {}
    for inc in incidents:
        n_act = 1 + (rng.random() < 0.2) if rng.random() < 0.95 else 0
        for _ in range(int(n_act)):
            t_open = inc["_opened"] + timedelta(minutes=rng.randint(10, 180))
            if t_open > as_of:
                continue
            ver_req = 1 if inc["severity"] == "CRITICAL" else int(rng.random() < (0.8 if inc["severity"] == "MAJOR" else 0.3))
            t_ip = t_open + timedelta(minutes=rng.randint(5, 240))
            t_comp = t_ip + timedelta(hours=min(120, max(1, rng.lognormvariate(math.log(8), 0.7))))
            t_ver = t_comp + timedelta(minutes=rng.randint(30, 1800)) if ver_req else None
            t_close = (t_ver if ver_req else t_comp) + timedelta(minutes=rng.randint(10, 720))
            stall = rng.random()
            max_stage = 4 if ver_req else 3
            if stall < 0.06:
                max_stage = 1
            elif stall < 0.11:
                max_stage = 2
            elif stall < 0.14 and ver_req:
                max_stage = 3
            plant = inc["_plant"]
            tech = f"TECH-{plant}-{rng.randint(1, 8):02d}"
            ver = f"SUP-{plant}-{rng.randint(1, 3):02d}"
            seq = [(None, "OPEN", t_open, f"SUP-{plant}-{rng.randint(1, 3):02d}")]
            stages = [("IN_PROGRESS", t_ip, tech), ("COMPLETED", t_comp, tech)]
            if ver_req:
                stages.append(("VERIFIED", t_ver, ver))
            stages.append(("CLOSED", t_close, ver))
            prev = "OPEN"
            for si, (st, tt, who) in enumerate(stages, 1):
                if si > max_stage or tt > as_of:
                    break
                seq.append((prev, st, tt, who))
                prev = st
            cat = inc["_cat"]
            atype = rng.choice(["ADJUST_GUARD", "REPLACE_SENSOR", "RECALIBRATE", "REPAIR"] if cat == "SAFETY_INTERLOCK"
                               else ["REPAIR", "INSPECTION", "SOFTWARE_FIX", "RECALIBRATE"])
            ts_of = {st: tt for _, st, tt, _ in seq}
            who_of = {st: w for _, st, _, w in seq}
            row = dict(action_id=f"CA-{len(actions) + 1:05d}", incident_id=inc["incident_id"], machine_id=inc["machine_id"],
                       action_type=atype, description=f"{atype.replace('_', ' ').capitalize()} following {inc['incident_type'].lower().replace('_', ' ')}.",
                       assigned_to=tech, verification_required=ver_req, status=prev, opened_ts=fmt(t_open),
                       completed_ts=fmt(ts_of["COMPLETED"]) if "COMPLETED" in ts_of else None,
                       verified_ts=fmt(ts_of["VERIFIED"]) if "VERIFIED" in ts_of else None,
                       verified_by=who_of.get("VERIFIED"),
                       closed_ts=fmt(ts_of["CLOSED"]) if "CLOSED" in ts_of else None, _inc=inc)
            actions.append(row)
            trans[row["action_id"]] = [list(s) for s in seq]
            inc.setdefault("_actions", []).append(row)
    for inc in incidents:
        acts = inc.get("_actions", [])
        if acts and all(a["status"] == "CLOSED" for a in acts):
            inc["status"] = "CLOSED"
            inc["closed_ts"] = fmt(max(_parse(a["closed_ts"]) for a in acts) + timedelta(minutes=rng.randint(1, 10)))
        elif acts:
            inc["status"] = "INVESTIGATING"

    # ---- injection: action closed without verification (edge case 5)
    cands = [a for a in actions if a["verification_required"] == 1 and a["status"] == "CLOSED"]
    for a in rng.sample(cands, min(p.inj_action_unverified, len(cands))):
        seq = [s for s in trans[a["action_id"]] if s[1] != "VERIFIED"]
        for i in range(1, len(seq)):
            seq[i][0] = seq[i - 1][1]
        trans[a["action_id"]] = seq
        a["verified_ts"], a["verified_by"] = None, None
        add_gt(5, "ACTION_CLOSED_WITHOUT_VERIFICATION", "corrective_actions", a["action_id"], a["incident_id"], "SKIPPED_VERIFIED_STEP",
               "Verification is mandatory but the action went COMPLETED -> CLOSED with no verification record.", "R-LC-01")
    cands = [a for a in actions if a["verification_required"] == 0 and a["status"] == "CLOSED"]
    for a in rng.sample(cands, min(p.ctl_unverified_not_required, len(cands))):
        controls.append(dict(control_type="CLOSED_WITHOUT_VERIFICATION_NOT_REQUIRED", table="corrective_actions", record_id=a["action_id"],
                             why_normal="Closed without verification, but verification_required = 0 for this action.",
                             expected_decision="NOT_FLAGGED"))

    # ---- injection: incident without triggering context (edge case 3)
    for k, inc in enumerate(rng.sample(incidents, min(p.inj_incident_no_context, len(incidents)))):
        v = ["BOTH_MISSING", "BOTH_MISSING", "ALARM_MISSING", "STATE_MISSING"][k % 4]
        if v in ("BOTH_MISSING", "ALARM_MISSING"):
            inc["trigger_alarm_event_id"] = None
        if v in ("BOTH_MISSING", "STATE_MISSING"):
            inc["machine_state_at_incident"] = None
        add_gt(3, "INCIDENT_WITHOUT_TRIGGERING_CONTEXT", "incidents", inc["incident_id"], "", v,
               "Incident exists without supporting alarm and/or machine-state evidence.", "R-IN-01")

    history, hn = [], 0
    for a in actions:
        for i, (frm, to, tt, who) in enumerate(trans[a["action_id"]], 1):
            hn += 1
            history.append(dict(history_id=f"CH-{hn:06d}", action_id=a["action_id"], seq=i, from_status=frm, to_status=to,
                                changed_ts=fmt(tt), changed_by=who))

    # ------------------------------------------------------------------ assemble
    for i, c in enumerate(controls, 1):
        c["control_id"] = f"CTL-{i:04d}"

    def proj(name, rows):
        cols = TABLES[name].col_names
        return [{c: r[c] for c in cols} for r in rows]

    tables = {
        "plants": proj("plants", plants), "safety_zones": proj("safety_zones", zones), "machines": proj("machines", machines),
        "interlocks": proj("interlocks", interlocks), "alarm_definitions": proj("alarm_definitions", alarm_defs),
        "operator_shifts": proj("operator_shifts", shifts), "alarm_events": proj("alarm_events", events),
        "acknowledgements": proj("acknowledgements", acks), "incidents": proj("incidents", incidents),
        "corrective_actions": proj("corrective_actions", actions),
        "corrective_action_history": proj("corrective_action_history", history),
    }
    gt_rows = [{c: r[c] for c in GROUND_TRUTH_COLUMNS} for r in gt]
    ctl_rows = [{c: r[c] for c in CONTROL_COLUMNS} for r in controls]
    meta = dict(profile=p.name, seed=seed, as_of=fmt(as_of), window_start=fmt(shift_base),
                chronic_machines=sorted(chronic),
                injected={k: sum(1 for g in gt_rows if g["anomaly_type"] == k) for k in sorted({g["anomaly_type"] for g in gt_rows})},
                controls=len(ctl_rows))
    return tables, gt_rows, ctl_rows, meta


def _parse(s):
    from datetime import datetime
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ")


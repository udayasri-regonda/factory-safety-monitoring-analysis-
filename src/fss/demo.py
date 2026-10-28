"""Demonstration feed: re-exports the generated alarm events in a DIFFERENT, vendor-style layout (other column names,
local IST timestamps in dd/mm/yyyy) and appends deliberately defective rows, so ingestion mapping, timestamp handling and
record validation are exercised on realistic records. This feed is SIMULATED; no real historian is involved."""
from __future__ import annotations

import csv
import os
from datetime import timedelta

from .exporters import parse_ts, read_csv

IST = timedelta(hours=5, minutes=30)
COLS = ["EvtId", "Asset", "AlarmRef", "InterlockRef", "RaisedLocal", "ClearedLocal", "MachineMode", "InterlockStatus", "SourceSys", "Batch", "LoadedAt"]
LOCAL = "%d/%m/%Y %H:%M:%S"

# (description, expected reason code) - expectations are written here by hand, independent of the ingest code
DEFECTS = [("missing event time", "MISSING_EVENT_TS"), ("unknown machine M999", "UNKNOWN_MACHINE"), ("duplicate event id", "DUPLICATE_EVENT_ID"),
           ("impossible date 31/02/2026", "BAD_EVENT_TS"), ("clear before raise", "CLEAR_BEFORE_EVENT"), ("unknown alarm AD-999", "UNKNOWN_ALARM_DEF"),
           ("missing event id", "MISSING_ALARM_EVENT_ID"), ("invalid machine mode", "INVALID_MACHINE_STATE")]


def _loc(s):
    return (parse_ts(s) + IST).strftime(LOCAL) if s else ""


def make_feed(out, path=None):
    path = path or os.path.join(out, "demo", "historian_export.csv")
    os.makedirs(os.path.dirname(path), exist_ok=True)
    ev = read_csv(os.path.join(out, "data", "csv", "alarm_events.csv"))
    rows = [[e["alarm_event_id"], e["machine_id"], e["alarm_def_id"], e["interlock_id"] or "", _loc(e["event_ts"]), _loc(e["clear_ts"]),
             e["machine_state"], e["interlock_state"], e["source_system"], e["ingest_batch_id"], _loc(e["ingested_ts"])] for e in ev]
    base = list(rows[10])
    def variant(**kw):
        r = list(base)
        for k, v in kw.items():
            r[COLS.index(k)] = v
        return r
    bad = [variant(EvtId="AE-BAD-001", RaisedLocal=""),
           variant(EvtId="AE-BAD-002", Asset="M999"),
           variant(EvtId=rows[20][0]),
           variant(EvtId="AE-BAD-004", RaisedLocal="31/02/2026 10:00:00"),
           variant(EvtId="AE-BAD-005", RaisedLocal="05/07/2026 10:00:00", ClearedLocal="05/07/2026 09:00:00"),
           variant(EvtId="AE-BAD-006", AlarmRef="AD-999"),
           variant(EvtId=""),
           variant(EvtId="AE-BAD-008", MachineMode="EXPLODING")]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(COLS)
        w.writerows(rows + bad)
    return path, len(rows), len(bad)

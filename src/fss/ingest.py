"""Ingestion + record-level validation of incoming alarm events.

A *mapping* (JSON) translates any source CSV layout into the canonical alarm_events fields, so the detection
engine never sees source-specific columns. Rows that cannot be trusted are quarantined with reason codes
(never silently dropped, never repaired).

Mapping format (see mappings/*.json and docs/integration_guide.md):
  {"source_name": "...",
   "fields":   {canonical_field: source_column, ...},
   "defaults": {canonical_field: constant, ...},        # used when a column is not mapped / cell is empty
   "timestamp": {"formats": ["%d/%m/%Y %H:%M:%S"], "source_timezone": "+05:30"}}
"""
from __future__ import annotations

import csv
import json
from datetime import datetime, timedelta, timezone

from .schema import MACHINE_STATES, INTERLOCK_STATES

CANONICAL = ["alarm_event_id", "alarm_def_id", "machine_id", "zone_id", "interlock_id", "event_ts", "clear_ts",
             "machine_state", "interlock_state", "source_system", "ingest_batch_id", "ingested_ts", "content_hash"]
REQUIRED = ["alarm_event_id", "alarm_def_id", "machine_id", "event_ts"]
TS_FIELDS = ("event_ts", "clear_ts", "ingested_ts")
OUT_FMT = "%Y-%m-%dT%H:%M:%SZ"

NATIVE_MAPPING = {"source_name": "native", "fields": {c: c for c in CANONICAL}, "defaults": {},
                  "timestamp": {"formats": [], "source_timezone": "UTC"}}


def load_mapping(path):
    with open(path, encoding="utf-8") as f:
        m = json.load(f)
    for k in ("fields",):
        if k not in m:
            raise ValueError(f"mapping file {path} is missing '{k}'")
    unknown = set(m["fields"]) - set(CANONICAL)
    if unknown:
        raise ValueError(f"mapping refers to unknown canonical fields: {sorted(unknown)}")
    m.setdefault("defaults", {})
    m.setdefault("timestamp", {"formats": [], "source_timezone": "UTC"})
    return m


def _tz(spec):
    """'UTC' | 'Z' | '+05:30' | '-0800'. Fixed offsets only (no DST rules) - documented limitation."""
    spec = (spec or "UTC").strip()
    if spec.upper() in ("UTC", "Z"):
        return timezone.utc
    sign = -1 if spec[0] == "-" else 1
    digits = spec.lstrip("+-").replace(":", "")
    if len(digits) != 4 or not digits.isdigit():
        raise ValueError(f"unsupported source_timezone '{spec}' (use UTC or a fixed offset like +05:30)")
    return timezone(sign * timedelta(hours=int(digits[:2]), minutes=int(digits[2:])))


def parse_timestamp(text, formats, tz):
    """Return a UTC string 'YYYY-MM-DDTHH:MM:SSZ' or raise ValueError. Fractional seconds are truncated."""
    s = str(text).strip()
    dt = None
    for fmt in formats:
        try:
            dt = datetime.strptime(s, fmt)
            break
        except ValueError:
            continue
    if dt is None:
        iso = s.replace("Z", "+00:00") if s.endswith("Z") else s
        if "." in iso:                                   # drop fractional seconds, keep any offset
            head, _, tail = iso.partition(".")
            k = next((i for i, ch in enumerate(tail) if ch in "+-"), len(tail))
            iso = head + tail[k:]
        dt = datetime.fromisoformat(iso)                  # ValueError if not ISO-8601
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=tz)
    dt = dt.astimezone(timezone.utc)
    if not 2000 <= dt.year <= 2100:
        raise ValueError("timestamp year outside 2000-2100")
    return dt.strftime(OUT_FMT)


def ingest_events(csv_path, mapping, machines, alarm_defs):
    """Read a source CSV, apply the mapping, validate every row.

    Returns dict(valid=[canonical rows], rejects=[...], summary={...}). `machines` / `alarm_defs` are the
    reference tables used for foreign-key checks.
    """
    fields, defaults = mapping["fields"], mapping.get("defaults", {})
    fmts = mapping["timestamp"].get("formats", [])
    tz = _tz(mapping["timestamp"].get("source_timezone", "UTC"))
    mach = {m["machine_id"]: m for m in machines}
    defs = {d["alarm_def_id"] for d in alarm_defs}
    valid, rejects, seen = [], [], {}
    total = 0

    with open(csv_path, newline="", encoding="utf-8-sig") as f:
        rd = csv.DictReader(f)
        missing_cols = [src for c, src in fields.items() if c in REQUIRED and src not in (rd.fieldnames or [])]
        if missing_cols:
            raise ValueError(f"source file lacks required mapped column(s): {missing_cols}")
        for n, raw in enumerate(rd, start=2):            # line 1 is the header
            total += 1
            row, codes, detail = {}, [], []
            for c in CANONICAL:
                src = fields.get(c)
                v = raw.get(src) if src else None
                v = v.strip() if isinstance(v, str) else v
                if v in (None, ""):
                    v = defaults.get(c)
                row[c] = v if v not in ("",) else None
            for c in REQUIRED:
                if row[c] is None:
                    codes.append(f"MISSING_{c.upper()}")
            for c in TS_FIELDS:
                if row[c] is not None:
                    try:
                        row[c] = parse_timestamp(row[c], fmts, tz)
                    except ValueError as e:
                        codes.append(f"BAD_{c.upper()}")
                        detail.append(f"{c}='{raw.get(fields.get(c))}' ({e})")
            if not codes:
                if row["machine_id"] not in mach:
                    codes.append("UNKNOWN_MACHINE")
                if row["alarm_def_id"] not in defs:
                    codes.append("UNKNOWN_ALARM_DEF")
                if row["clear_ts"] and row["clear_ts"] < row["event_ts"]:
                    codes.append("CLEAR_BEFORE_EVENT")
                if row["machine_state"] is not None and row["machine_state"] not in MACHINE_STATES:
                    codes.append("INVALID_MACHINE_STATE")
                if row["interlock_state"] is not None and row["interlock_state"] not in INTERLOCK_STATES:
                    codes.append("INVALID_INTERLOCK_STATE")
                if row["alarm_event_id"] in seen:
                    codes.append("DUPLICATE_EVENT_ID")
                    detail.append(f"first seen on source line {seen[row['alarm_event_id']]}")
            if codes:
                rejects.append(dict(source_line=n, alarm_event_id=row["alarm_event_id"], reasons="|".join(codes),
                                    detail="; ".join(detail), machine_id=row["machine_id"], raw_event_ts=raw.get(fields.get("event_ts"))))
                continue
            seen[row["alarm_event_id"]] = n
            row["zone_id"] = row["zone_id"] or mach[row["machine_id"]]["zone_id"]
            row["interlock_state"] = row["interlock_state"] or "NOT_APPLICABLE"
            row["machine_state"] = row["machine_state"] or "UNKNOWN"
            row["ingested_ts"] = row["ingested_ts"] or row["event_ts"]
            row["source_system"] = row["source_system"] or mapping.get("source_name", "UNKNOWN")
            row["ingest_batch_id"] = row["ingest_batch_id"] or "BATCH-UNSPECIFIED"
            row["content_hash"] = row["content_hash"] or ""
            valid.append(row)

    by_reason = {}
    for r in rejects:
        for code in r["reasons"].split("|"):
            by_reason[code] = by_reason.get(code, 0) + 1
    summary = dict(source_file=str(csv_path), source_name=mapping.get("source_name"), rows_read=total,
                   rows_valid=len(valid), rows_rejected=len(rejects), rejects_by_reason=dict(sorted(by_reason.items())),
                   source_timezone=mapping["timestamp"].get("source_timezone", "UTC"))
    return dict(valid=valid, rejects=rejects, summary=summary)

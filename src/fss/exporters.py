"""CSV / JSON / SQL / SQLite exporters, dataset loader, checksums, data dictionary."""
from __future__ import annotations

import csv
import hashlib
import json
import os
import sqlite3
from datetime import datetime

from .schema import TABLES, CREATE_ORDER, GROUND_TRUTH_COLUMNS, CONTROL_COLUMNS

INT_COLS = {(t.name, c.name) for t in TABLES.values() for c in t.cols if c.sqltype == "INTEGER"}


def parse_ts(s):
    return datetime.strptime(s, "%Y-%m-%dT%H:%M:%SZ") if s else None


def _mk(path):
    os.makedirs(path, exist_ok=True)
    return path


# ----------------------------------------------------------------------------- CSV / JSON
def write_csv(path, cols, rows):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f, lineterminator="\n")
        w.writerow(cols)
        for r in rows:
            w.writerow(["" if r[c] is None else r[c] for c in cols])


def read_csv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return [{k: (v if v != "" else None) for k, v in row.items()} for row in csv.DictReader(f)]


def write_dataset(out_dir, tables, gt_rows, ctl_rows):
    """Write CSV + JSON for every table and the (separate) ground-truth files."""
    for name, rows in tables.items():
        write_csv(os.path.join(_mk(os.path.join(out_dir, "data", "csv")), f"{name}.csv"), TABLES[name].col_names, rows)
        with open(os.path.join(_mk(os.path.join(out_dir, "data", "json")), f"{name}.json"), "w", encoding="utf-8") as f:
            json.dump(rows, f, separators=(",", ":"), ensure_ascii=False)
    gdir = _mk(os.path.join(out_dir, "ground_truth"))
    write_csv(os.path.join(gdir, "ground_truth.csv"), GROUND_TRUTH_COLUMNS, gt_rows)
    write_csv(os.path.join(gdir, "ground_truth_controls.csv"), CONTROL_COLUMNS, ctl_rows)
    write_sql(out_dir, tables)


def load_dataset(out_dir):
    """Load tables back from CSV (used by detector/validator so they work on files, not memory)."""
    tables = {}
    for name in CREATE_ORDER:
        rows = read_csv(os.path.join(out_dir, "data", "csv", f"{name}.csv"))
        for r in rows:
            for c in TABLES[name].col_names:
                if (name, c) in INT_COLS and r[c] is not None:
                    r[c] = int(r[c])
        tables[name] = rows
    return tables


# ----------------------------------------------------------------------------- SQL
def schema_sql():
    out = ["-- Factory Safety Monitoring schema (SQLite dialect; portable to PostgreSQL with minor edits)",
           "PRAGMA foreign_keys = ON;", ""]
    for name in CREATE_ORDER:
        t = TABLES[name]
        lines = []
        for c in t.cols:
            ln = f"  {c.name} {c.sqltype}"
            if c.name == t.pk:
                ln += " PRIMARY KEY"
            elif not c.nullable:
                ln += " NOT NULL"
            if c.allowed:
                vals = ", ".join(v if c.sqltype == "INTEGER" else f"'{v}'" for v in c.allowed)
                ln += f" CHECK ({c.name} IN ({vals}))" if not c.nullable else f" CHECK ({c.name} IS NULL OR {c.name} IN ({vals}))"
            lines.append(ln)
        for c in t.cols:
            if c.fk:
                rt, rc = c.fk.split(".")
                lines.append(f"  FOREIGN KEY ({c.name}) REFERENCES {rt}({rc})")
        out.append(f"-- {t.desc}")
        out.append(f"CREATE TABLE {name} (\n" + ",\n".join(lines) + "\n);")
        out.append("")
    idx = [("alarm_events", "machine_id, event_ts"), ("alarm_events", "alarm_def_id"), ("alarm_events", "content_hash"),
           ("acknowledgements", "alarm_event_id"), ("incidents", "machine_id"), ("corrective_actions", "incident_id"),
           ("corrective_action_history", "action_id, seq"), ("operator_shifts", "plant_id, zone_id, shift_start")]
    for tb, cols in idx:
        out.append(f"CREATE INDEX idx_{tb}_{cols.replace(', ', '_')} ON {tb}({cols});")
    out.append("")
    out.append("-- History preservation: append-only tables reject UPDATE and DELETE.")
    for name in CREATE_ORDER:
        if TABLES[name].append_only:
            for op in ("UPDATE", "DELETE"):
                out.append(f"CREATE TRIGGER trg_{name}_no_{op.lower()} BEFORE {op} ON {name}\n"
                           f"BEGIN SELECT RAISE(ABORT, '{name} is append-only'); END;")
    out.append("")
    return "\n".join(out)


def _lit(v):
    if v is None:
        return "NULL"
    if isinstance(v, int):
        return str(v)
    return "'" + str(v).replace("'", "''") + "'"


def write_sql(out_dir, tables):
    d = _mk(os.path.join(out_dir, "sql"))
    with open(os.path.join(d, "schema.sql"), "w", encoding="utf-8") as f:
        f.write(schema_sql())
    with open(os.path.join(d, "seed_data.sql"), "w", encoding="utf-8") as f:
        f.write("-- Seed data. Load after schema.sql.\nBEGIN TRANSACTION;\n")
        for name in CREATE_ORDER:
            cols = TABLES[name].col_names
            rows = tables[name]
            for i in range(0, len(rows), 200):
                chunk = rows[i:i + 200]
                vals = ",\n".join("(" + ",".join(_lit(r[c]) for c in cols) + ")" for r in chunk)
                f.write(f"INSERT INTO {name} ({', '.join(cols)}) VALUES\n{vals};\n")
        f.write("COMMIT;\n")


def build_sqlite(out_dir, tables):
    d = _mk(os.path.join(out_dir, "db"))
    path = os.path.join(d, "factory_safety.sqlite")
    if os.path.exists(path):
        os.remove(path)
    con = sqlite3.connect(path)
    con.executescript(schema_sql())
    for name in CREATE_ORDER:
        cols = TABLES[name].col_names
        con.executemany(f"INSERT INTO {name} ({','.join(cols)}) VALUES ({','.join('?' * len(cols))})",
                        [[r[c] for c in cols] for r in tables[name]])
    con.commit()
    fk = con.execute("PRAGMA foreign_key_check").fetchall()
    con.close()
    return path, len(fk)


# ----------------------------------------------------------------------------- checksums / docs
def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


DETERMINISTIC_DIRS = ("data", "sql", "ground_truth")


def checksums(out_dir):
    res = {}
    for sub in DETERMINISTIC_DIRS:
        base = os.path.join(out_dir, sub)
        for root, _, files in sorted(os.walk(base)):
            for fn in sorted(files):
                p = os.path.join(root, fn)
                res[os.path.relpath(p, out_dir)] = sha256_file(p)
    return res


def data_dictionary_md():
    L = ["# Data Dictionary", "",
         "Generated from `src/fss/schema.py` (the single source of truth for DDL, validation and this document).", "",
         "Conventions: timestamps are UTC ISO-8601 (`YYYY-MM-DDTHH:MM:SSZ`); NULL is an empty CSV cell / JSON `null`; "
         "`Allowed` lists the enumerated values enforced by `CHECK` constraints and by the validator.", ""]
    for name in CREATE_ORDER:
        t = TABLES[name]
        L += [f"## `{name}`", "", t.desc + (" **Append-only** (UPDATE/DELETE blocked by trigger)." if t.append_only else ""), "",
              f"Primary key: `{t.pk}`", "",
              "| Field | Type | Null? | Allowed values / FK | Description & validation rule |", "|---|---|---|---|---|"]
        for c in t.cols:
            extra = ", ".join(c.allowed) if c.allowed else ""
            if c.fk:
                extra = (extra + "; " if extra else "") + f"FK -> {c.fk}"
            if c.name == t.pk:
                extra = "PK"
            desc = c.desc + (f" **Rule:** {c.rule}" if c.rule else "")
            L.append(f"| `{c.name}` | {c.sqltype} | {'yes' if c.nullable else 'no'} | {extra} | {desc} |")
        L.append("")
    L += ["## Ground-truth files (kept separate from the data)", "",
          "`ground_truth/ground_truth.csv` - one row per injected anomaly: " + ", ".join(f"`{c}`" for c in GROUND_TRUTH_COLUMNS) + ".", "",
          "`ground_truth/ground_truth_controls.csv` - hard negatives that look suspicious but are valid; the detector must NOT flag them: "
          + ", ".join(f"`{c}`" for c in CONTROL_COLUMNS) + ".", ""]
    return "\n".join(L)

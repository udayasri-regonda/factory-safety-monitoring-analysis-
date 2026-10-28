# Integration guide: replacing the synthetic CSV with real factory data

The detection engine only sees the **canonical alarm-event schema**. A JSON *mapping* (see `mappings/`) translates any CSV layout into it,
so switching data sources means writing a mapping file, not changing code.

## 1. Canonical alarm event (what the engine needs)
| Field | Required | Notes |
|---|---|---|
| `alarm_event_id` | yes | Unique per event. Later rows re-using an ID are rejected (`DUPLICATE_EVENT_ID`). |
| `alarm_def_id` | yes | Must exist in `data/csv/alarm_definitions.csv` (severity, SLA, interlock expectations). |
| `machine_id` | yes | Must exist in `data/csv/machines.csv`. |
| `event_ts` | yes | Parsed to UTC, stored `YYYY-MM-DDTHH:MM:SSZ`. |
| `clear_ts` | no | Must not precede `event_ts`. |
| `machine_state` | no | One of RUNNING, IDLE, STOPPED, FAULT, MAINTENANCE, SETUP. If not supplied it becomes `UNKNOWN` and the unsafe-condition rule cannot fire for that event. |
| `interlock_state` | no | ENGAGED, DISENGAGED, BYPASSED, NOT_APPLICABLE (default). |
| `zone_id`, `interlock_id`, `source_system`, `ingest_batch_id`, `ingested_ts`, `content_hash` | no | Defaults are derived (zone from machine, `ingested_ts` = `event_ts`). |

Reference tables (plants, machines, alarm definitions, interlocks) and the optional history tables (acknowledgements, incidents, corrective actions) are read from `data/csv/` in the schema documented in `docs/data_dictionary.md`.
The engine needs acknowledgements/incidents/actions for the rules that use them; without them those rules simply produce no findings.

## 2. Mapping file
```json
{"source_name": "MY_HISTORIAN",
 "fields":   {"alarm_event_id": "EvtId", "machine_id": "Asset", "alarm_def_id": "AlarmRef", "event_ts": "RaisedLocal", "...": "..."},
 "defaults": {"source_system": "MY_HISTORIAN"},
 "timestamp": {"formats": ["%d/%m/%Y %H:%M:%S"], "source_timezone": "+05:30"}}
```
* `fields`: canonical name -> source column. Required fields must be mapped to a column that exists, otherwise ingestion stops with an error naming the column.
* `defaults`: constant used when a column is not mapped or a cell is empty.
* `timestamp.formats`: `strptime` formats tried first; otherwise ISO-8601 (with `Z` or an offset) is accepted.
* `timestamp.source_timezone`: applied to timestamps that carry no offset: `UTC` or a **fixed offset** such as `+05:30`.

Worked example: `mappings/example_historian_export.json` + `python run.py demo` (a simulated vendor layout with local IST timestamps).

## 3. Validation rules (record level, `src/fss/ingest.py`)
Rejected rows are quarantined and listed in the dashboard (Data quality) with line number and reason; they are never repaired or dropped silently.
`MISSING_<FIELD>`, `BAD_<TS_FIELD>`, `UNKNOWN_MACHINE`, `UNKNOWN_ALARM_DEF`, `CLEAR_BEFORE_EVENT`, `INVALID_MACHINE_STATE`, `INVALID_INTERLOCK_STATE`, `DUPLICATE_EVENT_ID`.
Content-level replays (same content, new ID) are **kept**, flagged by rule R-DU-01 and excluded from analytics (history is never deleted).
Cross-table checks (PK/FK, timelines, lifecycle) are in `reports/validation_report.md` from `run.py all`.

## 4. Commands
```
python run.py analyze --profile full --events path\to\events.csv --mapping path\to\mapping.json
python run.py serve   --profile full --events path\to\events.csv --mapping path\to\mapping.json
```

## 5. Limitations (read before deploying)
* **Nothing here talks to a PLC, SCADA, historian, CMMS or any factory system.** Integration is file-based (CSV). Connectors would have to be built and tested separately.
* Timezones: fixed offsets only. No DST rules or IANA zones (use UTC export, or one fixed offset per source). Sub-second precision is truncated; ordering of events inside one second is by event ID.
* Reference data (machines, alarm definitions with severities/SLAs/interlock expectations) must be supplied and maintained by the site; wrong reference data gives wrong findings.
* The whole file is processed in memory (50k events in about 8 s). Millions of rows would need a database-backed or chunked implementation.
* No authentication or authorisation; actor names are self-declared. Local, single-user prototype (binds to 127.0.0.1).
* Thresholds are defaults chosen for the synthetic data and documented, not calibrated on real plant data. Tune them with process experts.
* Ground-truth evaluation is only possible on synthetic data.

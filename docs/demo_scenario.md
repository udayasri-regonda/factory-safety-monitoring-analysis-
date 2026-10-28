# Demonstration scenario (all steps use stored pipeline data)

```
python run.py all --profile full        # generate data (seed 20261022), reports, native analysis   (~30 s)
python run.py demo --profile full       # vendor-style feed with 8 defective rows -> ingest -> findings
python run.py serve --profile full --events output\full\demo\historian_export.csv --mapping mappings\example_historian_export.json
```
Open http://127.0.0.1:8080 and enter your name (top right).

| Step | Do | Expected (full profile, seed 20261022) |
|---|---|---|
| 1-2 Ingest/validate | Data quality tab | 50,008 rows read, 50,000 valid, 8 rejected: one each of MISSING_EVENT_TS, UNKNOWN_MACHINE, DUPLICATE_EVENT_ID, BAD_EVENT_TS, CLEAR_BEFORE_EVENT, UNKNOWN_ALARM_DEF, MISSING_ALARM_EVENT_ID, INVALID_MACHINE_STATE |
| 3-4 Detect | Findings tab, rule R-UNS-01, severity CRITICAL | Findings such as `F-UNSF-E72568A7` (M001, 12 events). IDs are identical on every run. |
| 5 Evidence | Open it | Triggering alarms (RUNNING + DISENGAGED), their acknowledgements, related incidents, 3 context alarms before/after, in time order; missing evidence listed |
| 6 Risk factors | Same page | Components x weights = score; fleet and plant median shown; stated not to be a probability |
| 7 Action | "New corrective action" | Action WA-00001 appears with state OPEN; move it to IN_PROGRESS, COMPLETED |
| 8 Verification | Move to CLOSED | Banner: "Closed WITHOUT verification - NOT confirmed resolved". Try verifying with the owner's name: rejected. Verify with another person + written evidence: "Verified by an independent person" |
| 9 Re-run | Overview -> Re-run analysis | "digest IDENTICAL to the previous run"; review/action/verification preserved; finding count unchanged |
| 10 Export | "Export investigation (zip)" | `investigation_summary.md`, `evidence.csv`, `finding.json`, `risk_factors.json`, `actions.csv`, `manifest.json` (with SHA-256 of each file) |

`python -m unittest tests.test_fde.EndToEnd -v` performs exactly this sequence over HTTP and checks the results against the raw CSV and ground-truth files.

**Simulated:** all factory data; the "historian export" feed (re-formatted from the generated events, defects injected by `demo.py`).
**Functional:** ingestion mapping and timezone conversion, validation, rules, findings, SQLite storage, workflow rules, API, dashboard, export, reproducibility check.
**Needed for a real factory:** real exports plus site-maintained reference data and alarm definitions; threshold tuning with process-safety experts; authentication and user management; connectors (if wanted) built and tested against the real systems; validation by qualified safety personnel; a retention/backup policy; scaling beyond in-memory processing for very large histories.

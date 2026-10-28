# Factory Safety Monitoring & Analysis System

A data-driven industrial safety analysis system: it **generates** realistic factory event data (4 plants, 60 machines,
200 alarm definitions, 50,000 alarm events), **applies safety rules**, **detects** recurring unsafe conditions and
data-quality exceptions, **validates** integrity and history, and **proves** detection quality against a separate
ground-truth file. Pure Python 3.9+ standard library - nothing to install.

## Quick start (Windows PowerShell or cmd; macOS/Linux: use `python3`)
Prerequisite: Python 3.9+ (check with `python --version`). No packages to install, no virtual environment needed (standard library only).
```
cd factory_safety
python run.py all --profile full        # generate data (seed 20261022), validate, native analysis, reports   (~30 s)
python run.py demo --profile full       # simulated vendor feed with 8 defective rows -> ingest -> findings
python run.py serve --profile full --events output\full\demo\historian_export.csv --mapping mappings\example_historian_export.json
python -m unittest discover -s tests -v # 28 tests, ~40 s
```
Open **http://127.0.0.1:8080**. Stop the server with Ctrl+C. Use `--port 8081` if 8080 is busy. Without `--events` the server analyses `data/csv/alarm_events.csv`.
`python run.py all --profile starter` gives a 2,000-event dataset in seconds. Docker: `docker build -t fss . && docker run -p 8080:8080 fss`.

## Investigation workbench (new)
Dashboard tabs: Overview, Findings (filters), investigation view per finding (rule, severity rationale, observed vs inferred, chronological evidence, missing/contradictory evidence, risk factors, review, corrective actions, verification, export), Machine risk, Corrective actions, Data quality, Evaluation, Rules.
**Advisory only:** findings must be validated by qualified personnel; nothing controls equipment. Closing an action without independent verification is recorded as CLOSED_UNVERIFIED and never shown as resolved.
Docs: `docs/demo_scenario.md`, `docs/integration_guide.md`, `docs/architecture.md`, `docs/requirements_matrix.md`, `docs/validation_report.md`, `docs/known_limitations.md`.

## Commands (`python run.py <command> --profile starter|full --seed N --out DIR`)
| Command | What it does | Writes |
|---|---|---|
| `all` | generate -> detect -> validate -> metrics -> evaluate -> reproducibility -> static report -> workbench analysis | everything under `output/<profile>/` |
| `generate` | create data only | `data/`, `sql/`, `db/factory_safety.sqlite`, `ground_truth/`, `docs/`, `manifest.json` |
| `detect`, `evaluate`, `reproduce` | legacy report steps | `reports/*.csv/json/md` |
| `analyze [--events CSV --mapping JSON]` | ingest + findings into the workbench | `db/workbench.sqlite` |
| `demo` | build the simulated feed (`demo/historian_export.csv`) and analyse it | `demo/`, `db/workbench.sqlite` |
| `export --finding ID` | investigation zip | `exports/<ID>_investigation.zip` |
| `serve [--host --port --events --mapping]` | dashboard + API (127.0.0.1 only by default) | reads `db/workbench.sqlite` |

Troubleshooting: *"no such table / Could not load this page"* -> run `python run.py analyze` (or `demo`) first. *Port in use* -> `--port`. *"source file lacks required mapped column"* -> fix the mapping. On Windows use `python` if `python3` is not found.

## Original architecture (unchanged)

```
src/fss/schema.py      single source of truth: tables, types, enums, FKs  -> DDL, data dictionary, validator
src/fss/config.py      profiles, alarm catalogue, documented rule thresholds
src/fss/generator.py   seeded generator + injection of the 5 edge cases + ground truth + hard negatives
src/fss/exporters.py   CSV / JSON / SQL / SQLite writers, loader, checksums
src/fss/detector.py    5 anomaly rules + operational classification (unsafe/delayed/nuisance/flood/recurring)
src/fss/validate.py    PK, FK, NOT NULL, enum, timeline, lifecycle, scale checks
src/fss/metrics.py     KPIs, evaluation vs ground truth, dashboard
src/fss/pipeline.py    orchestration + reproducibility
```
**Separation of truth and detection:** `detector.py` loads only `data/csv/*.csv`. Labels live in `ground_truth/`
and are read only by the evaluation step. Hard-negative controls (e.g. ack in the same second as the alarm, repeat
alarms 1-2 s apart, actions closed unverified where verification is not required) test false positives.

## Output layout (`output/<profile>/`)
| Path | Content |
|---|---|
| `data/csv`, `data/json` | 11 tables (10 entities + `corrective_action_history`) |
| `sql/schema.sql`, `sql/seed_data.sql`, `db/factory_safety.sqlite` | DDL (keys, CHECKs, indexes, append-only triggers), seed inserts, ready DB |
| `ground_truth/` | `ground_truth.csv` (injected anomalies), `ground_truth_controls.csv` |
| `docs/data_dictionary.md` | every field, type, allowed values, rule |
| `reports/validation_report.md` | PK/FK/timeline/lifecycle/duplicate checks |
| `reports/metrics_summary.md`, `metrics.json` | KPIs: recurring unsafe, ack time, nuisance rate, verification rate |
| `reports/machine_risk_ranking.csv`, `event_classification.csv`, `findings_anomalies.csv` | traceable findings with reasons |
| `reports/evaluation_report.md` | precision / recall / F1 per anomaly type |
| `reports/reproducibility_report.md` | checksum evidence of identical re-runs |
| `reports/dashboard.html` | self-contained dashboard |
| `manifest.json` | seed, row counts, checksums |

Load the database yourself: `sqlite3 factory.db < sql/schema.sql && sqlite3 factory.db < sql/seed_data.sql`
(PostgreSQL: replace the `PRAGMA` line and the trigger bodies).

## Full-profile results (seed 20261022)
* Rows: 4 plants, 24 zones, 60 machines, 234 interlocks, 200 alarm definitions, 50,000 alarm events (incl. 150 replayed duplicates).
* 325 anomalies injected (60 ack-before-alarm, 60 impossible interlock states, 25 incidents without context, 150 duplicate replays, 30 unverified closures).
* Detection: precision 100%, recall 100% (on this synthetic ground truth; the controls produce 0 false positives).
  Treat 100% as a property of clean injected anomalies, not a field-performance claim - change injection variants to stress it.
* Structural validation: all PK/FK/enum/timeline checks pass. Re-run with same seed: byte-identical.

## Configuration
Change counts and injection volumes in `src/fss/config.py` (`PROFILES`); change rule thresholds in `RULES`;
change the seed with `--seed`. Same profile + seed always gives identical files. Rules are documented in `docs/business_rules.md`.

## Adapting to real data (deployment notes)
Replace the generator with an ingest job that fills the same 11 tables (see `docs/data_dictionary.md`); `detect`,
`validate`, `evaluate`-less reporting and the dashboard run unchanged on `data/csv/`. Schedule `run.py detect` nightly.

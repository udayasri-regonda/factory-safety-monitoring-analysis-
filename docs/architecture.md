# Architecture

```
 raw CSV --> ingest.py ---------> valid canonical events --+--> detector.py (rules, ops classification) --> findings.py (IDs, severity, evidence)
 (+mapping)  (map, UTC, validate)   rejects (quarantine)    |            |                                      |
 reference tables (data/csv) ------------------------------+        metrics.py (risk score, KPIs)              v
                                                                                                   store.py (SQLite workbench.sqlite)
 ground truth (synthetic only, read AFTER detection) --> metrics.evaluate -------------------------> |
                                                                                                      v
                                        workflow.py (review, actions, verification)  <-->  api.py  <-->  server.py  <-->  web/index.html
                                                                                                      \--> export.py (zip: summary + evidence)
```
| Component | Module | Responsibility |
|---|---|---|
| Ingestion | `ingest.py`, `mappings/*.json` | Source layout -> canonical schema, timestamps -> UTC |
| Validation | `ingest.py` (record), `validate.py` (cross-table) | Quarantine bad rows; structural integrity report |
| Detection | `detector.py` | Rule logic on canonical tables only (never sees ground truth) |
| Evaluation / metrics | `metrics.py` | Risk score (weights in `config.RISK_WEIGHTS`), KPIs, precision/recall vs ground truth |
| Findings | `findings.py` | Stable IDs, severity + rationale, observed vs inferred, chronological evidence, missing/contradictory evidence |
| Storage | `store.py` | SQLite. Derived tables rebuilt per run; human tables (review/actions/verifications/audit) preserved |
| Workflow | `workflow.py` | Review, corrective actions, verification, closure rules |
| Presentation | `api.py`, `server.py`, `web/index.html` | JSON API (all values queried from SQLite) + dashboard |
| Synthetic data | `generator.py`, `demo.py` | Seeded data (seed 20261022) and a simulated vendor-style feed with injected defects |

**Stable finding ID** = `F-<RULECODE>-<first 8 hex of sha1(rule|machine|anchor)>`; anchor = earliest triggering event/record. Re-runs on the same data give identical IDs; findings are upserted, never duplicated.
**Reproducibility digest** = sha256 of all findings + risk ranking + ingest summary (no timestamps or paths). The dashboard "Re-run analysis" button compares it with the previous run.
**Advisory only:** no component writes to or controls equipment.

# Requirements-to-implementation matrix

The original problem statement was not in the supplied project; the baseline is the existing README / `docs/business_rules.md` plus the "FDE end-to-end" requirement list you supplied. No extra mandatory requirements were invented.

| # | Requirement | Before | Now (evidence) | Status | Test |
|---|---|---|---|---|---|
| D1 | 4 plants, 60 machines, 200 alarm defs, 50,000 events | present | `config.PROFILES["full"]` | complete | `test_01_dataset_specification` |
| D2 | 30 days of history | **broken: 90 days** | full profile now 30 days | fixed | `test_01` |
| D3 | Seed 20261022 | **broken: seed 42** | `config.DEFAULT_SEED` | fixed | `test_01`, `Reproducibility` |
| D4 | Deterministic generation, FK/timestamps valid | present | generator + `validate.py` | complete | `test_pipeline`, `Reproducibility` |
| 1 | Ingest/load events | read in-process only | `ingest.py` + mapping files, `run.py analyze/demo` | complete | `test_02`, `IngestUnits` |
| 2 | Validate, identify invalid/missing records | table-level only | record-level quarantine with reason codes; UI "Data quality" | complete | `IngestUnits.test_validation_codes`, `test_02` |
| 3 | Documented, testable rules | 5 anomaly + ops rules | + 10 finding rules in `RULE_CATALOG`, thresholds in `config.RULES` | complete | `RuleUnits` |
| 4 | Finding with stable ID, severity, explanation, event IDs | anomaly CSV rows only | `findings.py` | complete | `test_stable_ids...`, `test_04` |
| 5 | Open finding, chronological evidence in dashboard | static HTML dashboard | `web/index.html` investigation view | complete (UI exercised manually with a browser; API + data behind it tested automatically) | `test_04` |
| 6 | Risk-score factors | single formula | per-factor count x weight, fleet/plant baseline | complete | `test_04` |
| 7 | Corrective action create/update | none | `workflow.py`, UI forms | complete | `WorkflowUnits`, `test_04` |
| 8 | Verification evidence; unverified closure is not resolution | flagged only | CLOSED_UNVERIFIED state, independent verifier, never "resolved" without verification | complete | `WorkflowUnits`, `test_04` |
| 9 | Re-run reproducibly | generator only | digest compare, idempotent upsert, human state preserved | complete | `test_04`, `Reproducibility` |
| 10 | Export summary + evidence | CSV reports | per-finding zip with manifest hashes | complete | `test_04` |
| E | Evaluation vs independent ground truth | present | shown in dashboard; only the 5 injected categories are scored | partial (other rules have no ground truth) | `test_03` |
| A | Advisory-only alerts | n/a | banner, finding text, no equipment interface | complete | `test_04` (advisory field) |
| Q | Optional investigation assistant (Phase 6) | none | **not implemented** (kept scope small); the investigation view shows evidence, rationale and missing evidence directly | missing | - |
| S | Seeded vs. real-time features (live PLC/SCADA/CMMS) | none | **not implemented, not claimed** | out of scope | - |

Fixed while auditing: alarms younger than the 3600 s grace period at the end of the data were counted as "unacknowledged" although the grace setting existed (`unack_grace_s` was unused).

# Known limitations and future work
* Synthetic data only; no live integration with PLC/SCADA/historian/CMMS exists or is claimed. See `docs/integration_guide.md`.
* Thresholds and severity rules are documented defaults, not calibrated on real plant data. The machine risk index is a relative ranking, not a probability.
* Evaluation covers only the five injected anomaly categories; flood, nuisance, repeated-alarm, acknowledgement-pattern and repeated-incident rules have no ground truth.
* Episode findings merge overlapping windows, so a long chain of qualifying windows becomes one finding (its observation window can span weeks). Nuisance findings are numerous (about 590 on the full dataset); filter by severity.
* No authentication; actor names are self-declared (audit log is append-only but not tamper-proof). Local single-user prototype.
* Fixed-offset timezones only; whole-file in-memory processing; no investigation assistant (Phase 6); the UI has no automated browser tests in the repository.
* Future: connectors, IANA timezones, auth/roles, incremental ingestion, recurrence monitoring after verification, calibrated risk model, a retrieval-based Q&A assistant over findings.

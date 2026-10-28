# Validation report

Executed 2026-10-28T10:25Z on Python 3.13.18 (Linux container). Command: `python -W ignore -m unittest discover -s tests -v`

**Result: 28 tests run, 28 passed, 0 failed** (6 pre-existing tests kept; 22 added in tests/test_fde.py).

```
test_01_dataset_specification ... ok
test_02_ingest_and_validation ... ok
test_03_every_ground_truth_anomaly_has_a_finding_and_controls_do_not ... ok
test_04_full_investigation_workflow ... ok
test_05_dashboard_and_error_handling ... ok
test_empty_file_and_missing_column ... ok
test_timezone_conversion ... ok
test_validation_codes ... ok
test_same_seed_same_files_and_pipeline_runs ... ok
test_ack_before_alarm_and_equal_timestamps ... ok
test_ack_delay_boundary ... ok
test_chatter_inside_and_outside_window ... ok
test_empty_dataset ... ok
test_episode_window_boundary ... ok
test_normal_machine_not_flagged ... ok
test_precision_recall_zero_denominators ... ok
test_stable_ids_independent_of_input_order ... ok
test_unacknowledged_high_alarm_and_end_of_window_grace ... ok
test_unverified_closure_finding ... ok
test_audit_log_is_append_only ... ok
test_invalid_transitions_and_early_verification ... ok
test_unverified_closure_is_not_resolution ... ok
test_append_only_triggers ... ok
test_detector_finds_all_injected_anomalies ... ok
test_reproducible ... ok
test_scale_exact ... ok
test_seed_sql_loads ... ok
test_structural_validation_passes ... ok
```

## Verified facts (full profile, seed 20261022)
* 4 plants, 60 machines, 200 alarm definitions, 50,000 alarm events, 30-day window (checked from the CSV files, `test_01`).
* Demo feed: 50,008 rows read, 50,000 valid, 8 rejected with the 8 expected reason codes; ingested events equal the native events (timestamps converted IST -> UTC).
* 1,377 findings; every one of the 325 injected anomalies is detected (4 types as findings, duplicates as flagged events); 0 hard-negative controls flagged.
* Re-running the analysis gives an identical digest, no duplicate findings, and preserves review/action/verification records.
* Export zip contents match the stored evidence; manifest SHA-256 values verified.
* Dashboard: exercised in a real Chromium session through Playwright (open finding, create/advance action, close unverified, verify, re-run, export download, all tabs) with no console or page errors. This browser run is a manual check, not part of the repository test suite.

## Not verified / not done
* Phase-6 investigation assistant not built.
* Performance beyond ~50k events, multi-user concurrency, Windows execution (commands were run on Linux; the code uses only the standard library and os.path).
* The 100% detection scores are on clean synthetic anomalies and say nothing about field performance.

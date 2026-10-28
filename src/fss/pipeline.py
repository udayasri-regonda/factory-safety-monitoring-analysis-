"""Pipeline orchestration: generate -> detect -> validate -> metrics -> evaluate -> reproduce."""
from __future__ import annotations

import json
import os
import shutil
import tempfile

from . import config as C
from . import exporters as X
from .detector import detect_anomalies, classify_operations
from .generator import generate
from .metrics import compute_metrics, evaluate, evaluation_md, summary_md, dashboard_html
from .validate import validate, report_md


def _w(path, text):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        f.write(text)


def _j(path, obj):
    _w(path, json.dumps(obj, indent=2, default=str))


def step_generate(out, profile, seed, with_sqlite=True):
    tables, gt, ctl, meta = generate(profile, seed)
    X.write_dataset(out, tables, gt, ctl)
    _w(os.path.join(out, "docs", "data_dictionary.md"), X.data_dictionary_md())
    info = {}
    if with_sqlite:
        path, fk_viol = X.build_sqlite(out, tables)
        info = dict(sqlite=os.path.relpath(path, out), sqlite_fk_violations=fk_viol)
    meta.update(info)
    meta["row_counts"] = {k: len(v) for k, v in tables.items()}
    meta["checksums_sha256"] = X.checksums(out)
    _j(os.path.join(out, "manifest.json"), meta)
    return meta


def step_detect(out):
    T = X.load_dataset(out)                      # reads the CSV files only; no ground truth involved
    anomalies = detect_anomalies(T)
    ops = classify_operations(T, anomalies)
    cols = ["rule_id", "anomaly_type", "table", "record_id", "related_record_id", "reason"]
    X.write_csv(os.path.join(out, "reports", "findings_anomalies.csv"), cols, anomalies)
    X.write_csv(os.path.join(out, "reports", "event_classification.csv"),
                ["alarm_event_id", "machine_id", "alarm_def_id", "classification", "flags"], ops["classification"])
    return T, anomalies, ops


def step_validate(out, T, profile):
    checks = validate(T, profile)
    _j(os.path.join(out, "reports", "validation_report.json"), checks)
    _w(os.path.join(out, "reports", "validation_report.md"), report_md(checks))
    return checks


def step_metrics(out, T, ops, anomalies):
    m = compute_metrics(T, ops, anomalies)
    ranking = m.pop("machine_risk_ranking")
    X.write_csv(os.path.join(out, "reports", "machine_risk_ranking.csv"), list(ranking[0].keys()), ranking)
    _j(os.path.join(out, "reports", "metrics.json"), m)
    return m


def step_evaluate(out, anomalies):
    gt = X.read_csv(os.path.join(out, "ground_truth", "ground_truth.csv"))
    ctl = X.read_csv(os.path.join(out, "ground_truth", "ground_truth_controls.csv"))
    ev = evaluate(anomalies, gt, ctl)
    _j(os.path.join(out, "reports", "evaluation_report.json"), ev)
    _w(os.path.join(out, "reports", "evaluation_report.md"), evaluation_md(ev))
    return ev


def step_reproduce(out, profile, seed):
    """Generate twice with the same seed (and once with seed+1) and compare checksums."""
    tmp = tempfile.mkdtemp(prefix="fss_repro_")
    try:
        sums, counts = [], []
        for tag, s in (("run1", seed), ("run2", seed), ("other", seed + 1)):
            d = os.path.join(tmp, tag)
            tables, gt, ctl, _ = generate(profile, s)
            X.write_dataset(d, tables, gt, ctl)
            sums.append(X.checksums(d))
            counts.append({k: len(v) for k, v in tables.items()})
        identical = sums[0] == sums[1]
        differs = sums[0] != sums[2]
        rep = dict(seed=seed, profile=profile.name, run1_equals_run2=identical, different_seed_gives_different_data=differs,
                   files_compared=len(sums[0]), row_counts=counts[0],
                   mismatched_files=[k for k in sums[0] if sums[0][k] != sums[1].get(k)], checksums_sha256_run1=sums[0],
                   checksums_sha256_run2=sums[1], note="SQLite binary is excluded (file header is not byte-stable); its content is built from the same rows.")
        _j(os.path.join(out, "reports", "reproducibility_report.json"), rep)
        md = ["# Reproducibility Report", "", f"Profile `{profile.name}`, seed `{seed}`.", "",
              f"- Run 1 and run 2 produce identical files: **{'YES' if identical else 'NO'}** ({len(sums[0])} files compared by SHA-256)",
              f"- Seed {seed + 1} produces different data (sanity check): **{'YES' if differs else 'NO'}**", "",
              "| File | SHA-256 (run 1) | SHA-256 (run 2) | Match |", "|---|---|---|---|"]
        for k in sorted(sums[0]):
            md.append(f"| {k} | `{sums[0][k][:16]}...` | `{sums[1][k][:16]}...` | {'yes' if sums[0][k] == sums[1][k] else 'NO'} |")
        _w(os.path.join(out, "reports", "reproducibility_report.md"), "\n".join(md) + "\n")
        return rep
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def run_all(out, profile_name="full", seed=C.DEFAULT_SEED, log=print):
    profile = C.PROFILES[profile_name]
    os.makedirs(out, exist_ok=True)
    log(f"[1/6] generating '{profile_name}' dataset (seed={seed}) -> {out}")
    meta = step_generate(out, profile, seed)
    log(f"      rows: {meta['row_counts']}")
    log(f"      injected anomalies: {meta['injected']}")
    log("[2/6] detecting anomalies and classifying alarm events")
    T, anomalies, ops = step_detect(out)
    log(f"      {len(anomalies)} anomaly findings")
    log("[3/6] validating")
    checks = step_validate(out, T, profile)
    ok = not any(c["status"] == "FAIL" for c in checks)
    log(f"      structural integrity: {'PASS' if ok else 'FAIL'}")
    log("[4/6] computing metrics")
    m = step_metrics(out, T, ops, anomalies)
    log("[5/6] evaluating detector against ground truth")
    ev = step_evaluate(out, anomalies)
    o = ev["overall"]
    log(f"      precision={o['precision']:.2%} recall={o['recall']:.2%} f1={o['f1']:.2%}")
    log("[6/6] reproducibility check (generating twice)")
    rep = step_reproduce(out, profile, seed)
    log(f"      identical on re-run: {rep['run1_equals_run2']}")
    _w(os.path.join(out, "reports", "metrics_summary.md"), summary_md(m, ev))
    html = dashboard_html(m, ev, ok, rep["run1_equals_run2"])
    _w(os.path.join(out, "reports", "dashboard.html"), html)
    _w(os.path.join(out, "reports", "index.html"), html)
    return dict(meta=meta, validation_ok=ok, evaluation=ev["overall"], reproducible=rep["run1_equals_run2"], metrics=m)

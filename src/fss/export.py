"""Investigation export: a zip with a human-readable summary and the supporting evidence, all read from the workbench DB."""
from __future__ import annotations

import csv
import hashlib
import io
import json
import zipfile

from . import api, store


def _csv(rows, cols):
    b = io.StringIO()
    w = csv.writer(b, lineterminator="\n")
    w.writerow(cols)
    for r in rows:
        w.writerow(["" if r.get(c) is None else r.get(c) for c in cols])
    return b.getvalue()


def summary_md(d, run):
    L = [f"# Investigation summary: {d['finding_id']}", "",
         f"> **ADVISORY.** {d['advisory']}", "",
         f"- **Title:** {d['title']}", f"- **Severity:** {d['severity']} - {d['severity_rationale']}",
         f"- **Rule:** {d['rule_id']} ({d['rule_name']}): {d['rule_logic']}",
         f"- **Plant / machine:** {d['plant_id']} / {d['machine_id']}", f"- **Observation window:** {d['window_start']} to {d['window_end']} (UTC)",
         f"- **Review status:** {d['review']['review_status']}" + (f" by {d['review']['reviewer']}: {d['review']['note']}" if d["review"]["reviewer"] else ""),
         f"- **Resolution status:** {d['resolution']['label']}",
         f"- **Analysis run:** #{run['run_id']} digest `{run['digest'][:16]}`", "",
         "## Observed facts (from records)", ""] + [f"- {x}" for x in d["observed"]] + ["", "## Interpretation (inferred, not confirmed)", "", d["inferred"], "",
         "## Chronological evidence", "", "| Time (UTC) | Record | ID | Role | Detail |", "|---|---|---|---|---|"]
    L += [f"| {e['ts']} | {e['record_type']} | {e['record_id']} | {e['role']} | {e['summary']} |" for e in d["evidence"]]
    L += ["", "## Missing evidence", ""] + ([f"- {m}" for m in d["missing_evidence"]] or ["- None identified from the available records."])
    L += ["", "## Contradictory evidence", ""] + ([f"- {m}" for m in d["contradictions"]] or ["- None identified."])
    mr = d.get("machine_risk")
    if mr:
        L += ["", f"## Machine risk factors ({d['machine_id']}, score {mr['score']}, rank {mr['rank']}, fleet median {mr['fleet_median_score']})", "",
              "| Factor | Count | Weight | Points |", "|---|---:|---:|---:|"] + [f"| {c['label']} | {c['count']} | {c['weight']} | {c['points']} |" for c in mr["components"]] + ["", mr["interpretation"]]
    L += ["", "## Corrective actions and verification", ""]
    if not d["actions"]:
        L.append("- No corrective action recorded in the workbench.")
    for a in d["actions"]:
        L.append(f"- **{a['wb_action_id']}** {a['description']} (owner {a['owner']}, due {a['due_date'] or 'n/a'}): {a['closure_state']}")
        for v in a["verifications"]:
            L.append(f"  - verified by {v['verified_by']} via {v['method']} at {v['verified_ts']}: {v['evidence_text']}")
    L += ["", "## Recommended investigation steps", ""] + [f"- {s}" for s in d["recommended_steps"]]
    return "\n".join(L) + "\n"


def build_bundle(con, fid):
    d = api.finding_detail(con, fid)
    if d is None:
        return None
    run = api._last_run(con)
    actions_rows = [dict(a, **{"verification": "; ".join(f"{v['verified_by']}:{v['evidence_text']}" for v in a["verifications"])}) for a in d["actions"]]
    files = {
        "investigation_summary.md": summary_md(d, run),
        "evidence.csv": _csv(d["evidence"], ["seq", "ts", "record_type", "record_id", "role", "summary"]),
        "finding.json": json.dumps({k: v for k, v in d.items() if k != "evidence"}, indent=2, sort_keys=True),
        "risk_factors.json": json.dumps(d["machine_risk"], indent=2, sort_keys=True),
        "actions.csv": _csv(actions_rows, ["wb_action_id", "description", "owner", "due_date", "status", "closure_state", "verification"]),
    }
    files["manifest.json"] = json.dumps(dict(finding_id=fid, run_id=run["run_id"], digest=run["digest"], exported_ts=store.now(),
                                             sha256={k: hashlib.sha256(v.encode()).hexdigest() for k, v in files.items()}), indent=2)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as z:
        for k, v in files.items():
            z.writestr(f"{fid}/{k}", v)
    return buf.getvalue(), files

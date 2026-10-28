"""Human workflow on findings: review, corrective actions, verification. All state lives in SQLite (store.py).

Closure rule: an action may be CLOSED without verification (work can finish), but it is then CLOSED_UNVERIFIED and the finding is
NEVER reported as resolved. A finding is VERIFIED_RESOLVED only when every action on it is CLOSED and has a verification record.
Verification needs a named verifier different from the action owner, a method and written evidence.
"""
from __future__ import annotations

from . import store

REVIEW_STATES = ("NEW", "UNDER_REVIEW", "CONFIRMED", "DISMISSED")
NEXT = {"OPEN": "IN_PROGRESS", "IN_PROGRESS": "COMPLETED", "COMPLETED": "CLOSED"}


class WorkflowError(ValueError):
    pass


def _need(v, name):
    if v is None or not str(v).strip():
        raise WorkflowError(f"'{name}' is required")
    return str(v).strip()


def _finding(con, fid):
    if not con.execute("SELECT 1 FROM findings WHERE finding_id=?", (fid,)).fetchone():
        raise WorkflowError(f"unknown finding '{fid}'")


def set_review(con, fid, status, reviewer, note=""):
    _finding(con, fid)
    if status not in REVIEW_STATES:
        raise WorkflowError(f"review status must be one of {REVIEW_STATES}")
    reviewer = _need(reviewer, "reviewer")
    con.execute("UPDATE review SET review_status=?, reviewer=?, note=?, reviewed_ts=? WHERE finding_id=?", (status, reviewer, note, store.now(), fid))
    store.audit(con, reviewer, "REVIEW", fid, f"{status}: {note}")
    con.commit()


def create_action(con, fid, description, owner, due_date, actor):
    _finding(con, fid)
    description, owner, actor = _need(description, "description"), _need(owner, "owner"), _need(actor, "actor")
    if due_date and len(due_date) != 10:
        raise WorkflowError("due_date must be YYYY-MM-DD")
    n = con.execute("SELECT COUNT(*) FROM wb_actions").fetchone()[0] + 1
    aid = f"WA-{n:05d}"
    con.execute("INSERT INTO wb_actions VALUES(?,?,?,?,?,?,?,NULL,NULL)", (aid, fid, description, owner, due_date or None, "OPEN", store.now()))
    store.audit(con, actor, "ACTION_CREATED", aid, f"finding={fid} owner={owner}")
    con.commit()
    return aid


def set_action_status(con, aid, new_status, actor):
    a = con.execute("SELECT * FROM wb_actions WHERE wb_action_id=?", (aid,)).fetchone()
    if not a:
        raise WorkflowError(f"unknown action '{aid}'")
    actor = _need(actor, "actor")
    if NEXT.get(a["status"]) != new_status:
        raise WorkflowError(f"invalid transition {a['status']} -> {new_status} (allowed next: {NEXT.get(a['status'], 'none')})")
    if new_status == "CLOSED":
        con.execute("UPDATE wb_actions SET status=?, closed_ts=?, closed_by=? WHERE wb_action_id=?", (new_status, store.now(), actor, aid))
    else:
        con.execute("UPDATE wb_actions SET status=? WHERE wb_action_id=?", (new_status, aid))
    has_v = con.execute("SELECT 1 FROM wb_verifications WHERE wb_action_id=?", (aid,)).fetchone()
    store.audit(con, actor, "ACTION_STATUS", aid, f"{a['status']}->{new_status}" + (" (CLOSED WITHOUT VERIFICATION)" if new_status == "CLOSED" and not has_v else ""))
    con.commit()


def add_verification(con, aid, verified_by, method, evidence_text, evidence_ref=""):
    a = con.execute("SELECT * FROM wb_actions WHERE wb_action_id=?", (aid,)).fetchone()
    if not a:
        raise WorkflowError(f"unknown action '{aid}'")
    verified_by, method, evidence_text = _need(verified_by, "verified_by"), _need(method, "method"), _need(evidence_text, "evidence_text")
    if len(evidence_text) < 10:
        raise WorkflowError("evidence_text must describe what was checked (at least 10 characters)")
    if a["status"] not in ("COMPLETED", "CLOSED"):
        raise WorkflowError("verification can only be recorded after the work is COMPLETED")
    if verified_by.lower() == a["owner"].lower():
        raise WorkflowError("verifier must be different from the action owner (independent verification)")
    n = con.execute("SELECT COUNT(*) FROM wb_verifications").fetchone()[0] + 1
    vid = f"WV-{n:05d}"
    con.execute("INSERT INTO wb_verifications VALUES(?,?,?,?,?,?,?)", (vid, aid, verified_by, method, evidence_text, evidence_ref or None, store.now()))
    store.audit(con, verified_by, "VERIFICATION", aid, f"{vid} method={method}")
    con.commit()
    return vid


def action_view(con, a):
    v = [dict(x) for x in con.execute("SELECT * FROM wb_verifications WHERE wb_action_id=? ORDER BY verified_ts", (a["wb_action_id"],))]
    d = dict(a)
    d["verifications"] = v
    d["verified"] = bool(v)
    d["closure_state"] = ("CLOSED_VERIFIED" if v else "CLOSED_UNVERIFIED") if a["status"] == "CLOSED" else a["status"]
    return d


def finding_resolution(actions):
    """actions: list of action_view dicts. Returns (code, label)."""
    if not actions:
        return "NO_ACTION", "No corrective action recorded"
    if any(a["status"] != "CLOSED" for a in actions):
        return "ACTION_IN_PROGRESS", "Corrective action in progress - not resolved"
    if any(not a["verified"] for a in actions):
        return "CLOSED_UNVERIFIED", "Closed WITHOUT verification - NOT confirmed resolved"
    return "VERIFIED_RESOLVED", "Verified by an independent person (advisory; keep monitoring for recurrence)"


def finding_actions(con, fid):
    return [action_view(con, a) for a in con.execute("SELECT * FROM wb_actions WHERE finding_id=? ORDER BY wb_action_id", (fid,))]

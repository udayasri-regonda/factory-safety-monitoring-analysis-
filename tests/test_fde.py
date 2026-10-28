"""Unit tests (hand-built data, hand-computed expectations) and the end-to-end workflow test (real pipeline data, real HTTP server).

Expected values are defined independently of the detector: by hand in the unit tests, from raw CSV / ground-truth files in the e2e test."""
import csv, hashlib, io, json, os, random, sys, tempfile, threading, unittest, urllib.request, urllib.error, zipfile
from datetime import datetime, timedelta
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from fss import config as C, pipeline as P, analysis, ingest, store, workflow as W, demo, server, findings as F
from fss.detector import detect_anomalies, classify_operations
from fss.metrics import evaluate

T0 = datetime(2026, 7, 1, 0, 0, 0)
ts = lambda sec: (T0 + timedelta(seconds=sec)).strftime("%Y-%m-%dT%H:%M:%SZ")


def mini(events, acks=(), incidents=(), actions=(), hist=(), defs=None):
    d = defs or [dict(alarm_def_id="D-LOW", alarm_code="LOW_A", severity="LOW", ack_sla_seconds=900, interlock_type=None, expected_interlock_states="NOT_APPLICABLE", requires_incident=0, nuisance_candidate=1),
                 dict(alarm_def_id="D-HI", alarm_code="HI_A", severity="HIGH", ack_sla_seconds=120, interlock_type=None, expected_interlock_states="NOT_APPLICABLE", requires_incident=0, nuisance_candidate=0)]
    ms = [dict(machine_id=m, plant_id="P1", zone_id="Z1", machine_name=m, machine_type="X", criticality="LOW") for m in ("M1", "M2")]
    full = []
    for i, (eid, m, dd, sec) in enumerate(events):
        full.append(dict(alarm_event_id=eid, alarm_def_id=dd, machine_id=m, zone_id="Z1", interlock_id=None, event_ts=ts(sec), clear_ts=None, machine_state="IDLE",
                         interlock_state="NOT_APPLICABLE", source_system="T", ingest_batch_id="B", ingested_ts=ts(sec), content_hash=""))
    return dict(plants=[dict(plant_id="P1", plant_name="P")], machines=ms, alarm_definitions=d, interlocks=[], alarm_events=full,
                acknowledgements=[dict(ack_id=a, alarm_event_id=e, operator_id="O", shift_id="S", ack_ts=ts(s), ack_method="HMI", comment=None) for a, e, s in acks],
                incidents=list(incidents), corrective_actions=list(actions), corrective_action_history=list(hist), safety_zones=[], operator_shifts=[])


def run(T):
    an = detect_anomalies(T)
    ops = classify_operations(T, an)
    return an, ops, F.build_findings(T, ops, an)


class RuleUnits(unittest.TestCase):
    def test_episode_window_boundary(self):
        mk = lambda secs: [dict(_t=T0 + timedelta(seconds=s), alarm_event_id=f"E{i}") for i, s in enumerate(secs)]
        ep = lambda secs: F.episodes(mk(secs), timedelta(seconds=600), 3, lambda e: e["_t"], lambda e: e["alarm_event_id"])
        self.assertEqual(len(ep([0, 300, 600])), 1)        # exactly 600 s apart: inside the window
        self.assertEqual(len(ep([0, 300, 601])), 0)        # 601 s: outside
        self.assertEqual(len(ep([0, 100, 200, 5000, 5100, 5200])), 2)
        self.assertEqual(len(ep([])), 0)

    def test_chatter_inside_and_outside_window(self):
        inside = mini([("E1", "M1", "D-LOW", 0), ("E2", "M1", "D-LOW", 200), ("E3", "M1", "D-LOW", 400)])
        outside = mini([("E1", "M2", "D-LOW", 0), ("E2", "M2", "D-LOW", 700), ("E3", "M2", "D-LOW", 1400)])
        self.assertEqual([f["rule_id"] for f in run(inside)[2]], ["R-NUIS-01"])
        self.assertEqual(run(outside)[2], [])

    def test_normal_machine_not_flagged(self):
        T = mini([("E1", "M1", "D-LOW", 0), ("E2", "M1", "D-HI", 100000)], acks=[("A1", "E2", 100030)])
        an, ops, fs = run(T)
        self.assertEqual((an, fs), ([], []))
        self.assertEqual(ops["flags"]["E2"] if "E2" in ops["flags"] else set(), set())

    def test_unacknowledged_high_alarm_and_end_of_window_grace(self):
        T = mini([("E1", "M1", "D-HI", 0), ("E2", "M1", "D-HI", 90000), ("E3", "M1", "D-HI", 90000 + 3600 - 1)], acks=[])
        # dataset ends at E3. E1 is old -> unacknowledged. E2 is 3599s older than the end... use explicit as_of for clarity
        an = detect_anomalies(T)
        ops = classify_operations(T, an, as_of=T0 + timedelta(seconds=90000 + 3600))
        self.assertIn("UNACKNOWLEDGED", ops["flags"]["E1"])
        self.assertIn("UNACKNOWLEDGED", ops["flags"]["E2"])            # exactly at the grace boundary -> overdue
        self.assertNotIn("UNACKNOWLEDGED", ops["flags"]["E3"])         # 1 s inside grace -> not yet overdue

    def test_ack_delay_boundary(self):
        T = mini([("E1", "M1", "D-HI", 0), ("E2", "M1", "D-HI", 1000)], acks=[("A1", "E1", 120), ("A2", "E2", 1121)])   # SLA 120 s
        ops = classify_operations(T, detect_anomalies(T))
        self.assertNotIn("DELAYED_ACK", ops["flags"]["E1"])   # exactly at SLA
        self.assertIn("DELAYED_ACK", ops["flags"]["E2"])      # SLA + 1 s

    def test_ack_before_alarm_and_equal_timestamps(self):
        T = mini([("E1", "M1", "D-HI", 100), ("E2", "M1", "D-HI", 5000)], acks=[("A1", "E1", 90), ("A2", "E2", 5000)])
        an = detect_anomalies(T)
        self.assertEqual([(f["rule_id"], f["record_id"]) for f in an], [("R-TL-01", "A1")])

    def test_unverified_closure_finding(self):
        inc = [dict(incident_id="I1", machine_id="M1", zone_id="Z1", trigger_alarm_event_id=None, machine_state_at_incident=None, incident_type="X", severity="MAJOR",
                    opened_ts=ts(10), closed_ts=None, status="OPEN", description="")]
        act = [dict(action_id="CA1", incident_id="I1", machine_id="M1", action_type="FIX", description="", assigned_to="T", verification_required=1, status="CLOSED",
                    opened_ts=ts(20), completed_ts=ts(30), verified_ts=None, verified_by=None, closed_ts=ts(40))]
        hist = [dict(history_id=f"H{i}", action_id="CA1", seq=i, from_status=a, to_status=b, changed_ts=ts(20 + i), changed_by="x")
                for i, (a, b) in enumerate([(None, "OPEN"), ("OPEN", "IN_PROGRESS"), ("IN_PROGRESS", "COMPLETED"), ("COMPLETED", "CLOSED")], 1)]
        T = mini([], incidents=inc, actions=act, hist=hist)
        fs = run(T)[2]
        self.assertEqual(sorted(f["rule_id"] for f in fs), ["R-IN-01", "R-LC-01"])      # incident also lacks trigger + state
        lc = next(f for f in fs if f["rule_id"] == "R-LC-01")
        self.assertEqual(lc["severity"], "HIGH")                                        # MAJOR incident
        self.assertIn("Verification evidence unavailable (no verified_ts)", lc["missing_evidence"])

    def test_stable_ids_independent_of_input_order(self):
        evs = [(f"E{i}", "M1", "D-LOW", i * 100) for i in range(5)]
        a = run(mini(evs))[2]
        shuffled = list(evs); random.Random(1).shuffle(shuffled)
        b = run(mini(shuffled))[2]
        self.assertEqual([f["finding_id"] for f in a], [f["finding_id"] for f in b])
        self.assertEqual(len(a), 1)
        self.assertTrue(a[0]["finding_id"].startswith("F-NUIS-"))

    def test_empty_dataset(self):
        self.assertEqual(run(mini([]))[2], [])

    def test_precision_recall_zero_denominators(self):
        e = evaluate([], [], [])
        self.assertEqual((e["overall"]["true_positives"], e["overall"]["false_positives"], e["overall"]["false_negatives"]), (0, 0, 0))
        e = evaluate([dict(anomaly_type="A", record_id="1", table="t")], [], [])        # only false positives
        self.assertEqual((e["overall"]["precision"], e["overall"]["f1"]), (0.0, 0.0))
        e = evaluate([dict(anomaly_type="A", record_id="1", table="t")], [dict(anomaly_type="A", record_id="1"), dict(anomaly_type="A", record_id="2")], [])
        self.assertEqual((e["overall"]["true_positives"], e["overall"]["false_negatives"], e["overall"]["recall"]), (1, 1, 0.5))


class IngestUnits(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.mach = [dict(machine_id="M1", zone_id="Z1")]
        self.defs = [dict(alarm_def_id="D1")]

    def feed(self, rows, cols=("id", "m", "d", "t", "c", "ms")):
        p = os.path.join(self.tmp, "f.csv")
        with open(p, "w", newline="") as f:
            w = csv.writer(f); w.writerow(cols); w.writerows(rows)
        return p

    MAP = {"source_name": "t", "fields": {"alarm_event_id": "id", "machine_id": "m", "alarm_def_id": "d", "event_ts": "t", "clear_ts": "c", "machine_state": "ms"},
           "defaults": {}, "timestamp": {"formats": ["%d/%m/%Y %H:%M:%S"], "source_timezone": "+05:30"}}

    def test_timezone_conversion(self):
        self.assertEqual(ingest.parse_timestamp("01/07/2026 05:30:00", ["%d/%m/%Y %H:%M:%S"], ingest._tz("+05:30")), "2026-07-01T00:00:00Z")
        self.assertEqual(ingest.parse_timestamp("01/07/2026 00:10:00", ["%d/%m/%Y %H:%M:%S"], ingest._tz("+05:30")), "2026-06-30T18:40:00Z")   # crosses midnight
        self.assertEqual(ingest.parse_timestamp("2026-07-01T10:00:00+02:00", [], ingest._tz("UTC")), "2026-07-01T08:00:00Z")
        self.assertEqual(ingest.parse_timestamp("2026-07-01T10:00:00.987Z", [], ingest._tz("+05:30")), "2026-07-01T10:00:00Z")
        with self.assertRaises(ValueError):
            ingest.parse_timestamp("not a date", [], ingest._tz("UTC"))

    def test_validation_codes(self):
        p = self.feed([["A1", "M1", "D1", "01/07/2026 10:00:00", "", "RUNNING"],      # good
                       ["A1", "M1", "D1", "01/07/2026 11:00:00", "", "RUNNING"],      # duplicate id
                       ["A2", "M9", "D1", "01/07/2026 10:00:00", "", "RUNNING"],      # unknown machine
                       ["A3", "M1", "D1", "", "", "RUNNING"],                         # missing ts
                       ["", "M1", "D1", "01/07/2026 10:00:00", "", "RUNNING"],        # missing id
                       ["A5", "M1", "D1", "01/07/2026 10:00:00", "01/07/2026 09:00:00", "RUNNING"],   # clear before event
                       ["A6", "M1", "D1", "32/07/2026 10:00:00", "", "RUNNING"],      # bad date
                       ["A7", "M1", "DX", "01/07/2026 10:00:00", "", "RUNNING"],      # unknown def
                       ["A8", "M1", "D1", "01/07/2026 10:00:00", "", "FLYING"]])      # bad enum
        r = ingest.ingest_events(p, self.MAP, self.mach, self.defs)
        self.assertEqual([e["alarm_event_id"] for e in r["valid"]], ["A1"])
        self.assertEqual(r["valid"][0]["event_ts"], "2026-07-01T04:30:00Z")
        self.assertEqual([x["reasons"] for x in r["rejects"]], ["DUPLICATE_EVENT_ID", "UNKNOWN_MACHINE", "MISSING_EVENT_TS", "MISSING_ALARM_EVENT_ID",
                                                               "CLEAR_BEFORE_EVENT", "BAD_EVENT_TS", "UNKNOWN_ALARM_DEF", "INVALID_MACHINE_STATE"])
        self.assertEqual(r["summary"]["rows_read"], 9)

    def test_empty_file_and_missing_column(self):
        r = ingest.ingest_events(self.feed([]), self.MAP, self.mach, self.defs)
        self.assertEqual((r["valid"], r["rejects"]), ([], []))
        with self.assertRaises(ValueError):
            ingest.ingest_events(self.feed([], cols=("id", "m")), self.MAP, self.mach, self.defs)


class WorkflowUnits(unittest.TestCase):
    def setUp(self):
        self.con = store.connect(":memory:")
        self.con.execute("INSERT INTO findings(finding_id,rule_id,rule_name,category,plant_id,machine_id,title,severity,window_start,window_end,detail_json,active) VALUES('F-X','R','r','c','P1','M1','t','HIGH','a','b','{}',1)")
        self.con.execute("INSERT INTO review(finding_id) VALUES('F-X')")

    def acts(self):
        return W.finding_actions(self.con, "F-X")

    def test_unverified_closure_is_not_resolution(self):
        self.assertEqual(W.finding_resolution(self.acts())[0], "NO_ACTION")
        a = W.create_action(self.con, "F-X", "Replace guard switch", "tech1", "2026-08-01", "sup")
        for s in ("IN_PROGRESS", "COMPLETED", "CLOSED"):
            W.set_action_status(self.con, a, s, "tech1")
        self.assertEqual(self.acts()[0]["closure_state"], "CLOSED_UNVERIFIED")
        self.assertEqual(W.finding_resolution(self.acts())[0], "CLOSED_UNVERIFIED")     # NOT resolved
        with self.assertRaises(W.WorkflowError):
            W.add_verification(self.con, a, "tech1", "inspection", "checked the switch works properly")   # owner cannot self-verify
        with self.assertRaises(W.WorkflowError):
            W.add_verification(self.con, a, "sup", "inspection", "ok")                  # evidence too thin
        W.add_verification(self.con, a, "sup", "inspection", "Tested guard interlock 10 cycles, stops machine each time", "PHOTO-12")
        self.assertEqual(W.finding_resolution(self.acts())[0], "VERIFIED_RESOLVED")

    def test_invalid_transitions_and_early_verification(self):
        a = W.create_action(self.con, "F-X", "Fix", "tech1", None, "sup")
        with self.assertRaises(W.WorkflowError):
            W.set_action_status(self.con, a, "CLOSED", "sup")                           # cannot skip
        with self.assertRaises(W.WorkflowError):
            W.add_verification(self.con, a, "sup", "inspection", "looked at it carefully")  # not completed yet
        self.assertEqual(W.finding_resolution(self.acts())[0], "ACTION_IN_PROGRESS")
        with self.assertRaises(W.WorkflowError):
            W.create_action(self.con, "F-NOPE", "x", "y", None, "z")

    def test_audit_log_is_append_only(self):
        W.set_review(self.con, "F-X", "CONFIRMED", "qa", "seen")
        import sqlite3
        with self.assertRaises(sqlite3.DatabaseError):
            self.con.execute("DELETE FROM audit_log")


# ----------------------------------------------------------------------------------------------- end to end
def http(base, path, method="GET", body=None):
    req = urllib.request.Request(base + path, method=method, data=json.dumps(body).encode() if body is not None else None, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=120) as r:
            raw = r.read()
            return r.status, (raw if r.headers.get("Content-Type", "").startswith(("application/zip", "text/html")) else json.loads(raw))
    except urllib.error.HTTPError as e:
        return e.code, json.loads(e.read())


def rcsv(path):
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


class EndToEnd(unittest.TestCase):
    """Full profile, real pipeline files, real HTTP server, real SQLite. Nothing is mocked."""

    @classmethod
    def setUpClass(cls):
        cls.out = tempfile.mkdtemp()
        cls.meta = P.step_generate(cls.out, C.PROFILES["full"], C.DEFAULT_SEED)
        cls.feed, cls.n_good, cls.n_bad = demo.make_feed(cls.out)
        cls.mapping = os.path.join(os.path.dirname(__file__), "..", "mappings", "example_historian_export.json")
        cls.app = server.App(cls.out, cls.feed, cls.mapping)
        cls.res = analysis.run_analysis(cls.out, cls.feed, cls.mapping)
        cls.srv = server.make_server(cls.app, "127.0.0.1", 0)
        threading.Thread(target=cls.srv.serve_forever, daemon=True).start()
        cls.base = f"http://127.0.0.1:{cls.srv.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.srv.shutdown(); cls.srv.server_close()

    def test_01_dataset_specification(self):
        d = os.path.join(self.out, "data", "csv")
        counts = {t: len(rcsv(os.path.join(d, f"{t}.csv"))) for t in ("plants", "machines", "alarm_definitions", "alarm_events")}
        self.assertEqual(counts, {"plants": 4, "machines": 60, "alarm_definitions": 200, "alarm_events": 50000})
        self.assertEqual(C.DEFAULT_SEED, 20261022)
        self.assertEqual(self.meta["seed"], 20261022)
        t0 = datetime.strptime(self.meta["window_start"], "%Y-%m-%dT%H:%M:%SZ"); t1 = datetime.strptime(self.meta["as_of"], "%Y-%m-%dT%H:%M:%SZ")
        self.assertEqual((t1 - t0).days, 30)
        ev = rcsv(os.path.join(d, "alarm_events.csv"))
        self.assertEqual(len({e["alarm_event_id"] for e in ev}), 50000)
        self.assertTrue(all(t0 <= datetime.strptime(e["event_ts"], "%Y-%m-%dT%H:%M:%SZ") <= t1 for e in ev))
        self.assertEqual({e["machine_id"] for e in ev} - {m["machine_id"] for m in rcsv(os.path.join(d, "machines.csv"))}, set())

    def test_02_ingest_and_validation(self):
        s = self.res["summary"]["ingest"]
        self.assertEqual((s["rows_read"], s["rows_valid"], s["rows_rejected"]), (50008, 50000, 8))
        self.assertEqual(sorted(s["rejects_by_reason"]), sorted(code for _, code in demo.DEFECTS))
        # feed (local IST, other column names) must round-trip to the native UTC events exactly
        native = {e["alarm_event_id"]: e for e in rcsv(os.path.join(self.out, "data", "csv", "alarm_events.csv"))}
        self.assertEqual(len(self.res["T"]["alarm_events"]), len(native))
        for e in self.res["T"]["alarm_events"][::97]:
            n = native[e["alarm_event_id"]]
            self.assertEqual((e["event_ts"], e["clear_ts"] or "", e["machine_id"], e["machine_state"]), (n["event_ts"], n["clear_ts"], n["machine_id"], n["machine_state"]))
        st, q = http(self.base, "/api/quality")
        self.assertEqual(len(q["rejects"]), 8)

    def test_03_every_ground_truth_anomaly_has_a_finding_and_controls_do_not(self):
        gt = rcsv(os.path.join(self.out, "ground_truth", "ground_truth.csv"))
        ctl = rcsv(os.path.join(self.out, "ground_truth", "ground_truth_controls.csv"))
        con = store.connect(self.app.db)
        anchors = {(r["rule_id"], json.loads(r["detail_json"])["anchor"]) for r in con.execute("SELECT rule_id, detail_json FROM findings WHERE active=1")}
        dups = {r["alarm_event_id"] for r in con.execute("SELECT alarm_event_id FROM events WHERE classification='DUPLICATE'")}
        want = {"ACK_BEFORE_ALARM": "R-TL-01", "IMPOSSIBLE_INTERLOCK_STATE": "R-ST-01", "INCIDENT_WITHOUT_TRIGGERING_CONTEXT": "R-IN-01", "ACTION_CLOSED_WITHOUT_VERIFICATION": "R-LC-01"}
        missed = []
        for g in gt:
            if g["anomaly_type"] == "DUPLICATE_ALARM_REPLAY":
                if g["record_id"] not in dups:
                    missed.append(g["record_id"])
            elif (want[g["anomaly_type"]], g["record_id"]) not in anchors:
                missed.append(g["record_id"])
        self.assertEqual(missed, [])
        self.assertEqual(len(gt), 325)
        wrongly = [c["record_id"] for c in ctl if any(c["record_id"] == a for _, a in anchors if _ in want.values()) or c["record_id"] in dups]
        self.assertEqual(wrongly, [])
        st, ev = http(self.base, "/api/evaluation")
        self.assertEqual((ev["evaluation"]["overall"]["false_positives"], ev["evaluation"]["overall"]["false_negatives"]), (0, 0))

    def test_04_full_investigation_workflow(self):
        b = self.base
        st, ov = http(b, "/api/overview")
        self.assertEqual((ov["totals"]["machines"], ov["totals"]["alarm_events"], ov["totals"]["plants"]), (60, 50000, 4))
        self.assertEqual(sum(ov["findings_by_severity"].values()), ov["totals"]["findings"])
        self.assertEqual(sum(d["n"] for d in ov["alarm_volume_by_day"]), 50000)

        # 5. open a finding and inspect chronological evidence (checked against raw CSV, not against the detector)
        st, lst = http(b, "/api/findings?rule=R-UNS-01&severity=CRITICAL")
        self.assertGreater(lst["total"], 0)
        fid = lst["items"][0]["finding_id"]
        st, d = http(b, f"/api/findings/{fid}")
        self.assertRegex(fid, r"^F-UNSF-[0-9A-F]{8}$")
        raw = {e["alarm_event_id"]: e for e in rcsv(os.path.join(self.out, "data", "csv", "alarm_events.csv"))}
        trig = [e for e in d["evidence"] if e["role"] == "TRIGGER"]
        self.assertGreaterEqual(len(trig), 3)
        self.assertEqual([t["record_id"] for t in trig], d["trigger_event_ids"])
        for t in trig:
            r = raw[t["record_id"]]
            self.assertEqual((r["machine_id"], r["machine_state"], r["interlock_state"], r["event_ts"]), (d["machine_id"], "RUNNING", "DISENGAGED", t["ts"]))
        self.assertEqual([e["ts"] for e in d["evidence"]], sorted(e["ts"] for e in d["evidence"]))
        self.assertIn("Advisory", d["advisory"])
        self.assertTrue(d["observed"] and d["inferred"] and d["severity_rationale"] and d["rule_logic"])

        # 6. risk factors: components sum to the score and match an independent count from raw data
        mr = d["machine_risk"]
        self.assertAlmostEqual(sum(c["points"] for c in mr["components"]), mr["score"], places=6)
        dup_ids = {g["record_id"] for g in rcsv(os.path.join(self.out, "ground_truth", "ground_truth.csv")) if g["anomaly_type"] == "DUPLICATE_ALARM_REPLAY"}
        unsafe = sum(1 for e in raw.values() if e["machine_id"] == d["machine_id"] and e["machine_state"] == "RUNNING" and e["interlock_state"] == "DISENGAGED" and e["alarm_event_id"] not in dup_ids)
        self.assertEqual(next(c["count"] for c in mr["components"] if c["factor"] == "UNSAFE_CONDITION"), unsafe)

        # review requires a name; human decision is stored
        self.assertEqual(http(b, f"/api/findings/{fid}/review", "POST", {"status": "CONFIRMED", "reviewer": ""})[0], 400)
        st, d = http(b, f"/api/findings/{fid}/review", "POST", {"status": "UNDER_REVIEW", "reviewer": "Priya", "note": "inspecting guard"})
        self.assertEqual(d["review"]["review_status"], "UNDER_REVIEW")

        # 7. corrective action
        st, c = http(b, f"/api/findings/{fid}/actions", "POST", {"description": "Replace guard door switch", "owner": "tech.ravi", "due_date": "2026-07-15", "actor": "Priya"})
        self.assertEqual(st, 201); aid = c["wb_action_id"]
        self.assertEqual(http(b, f"/api/actions/{aid}/verify", "POST", {"verified_by": "sup.anita", "method": "inspection", "evidence_text": "checked everything ok"})[0], 400)  # not completed
        for s in ("IN_PROGRESS", "COMPLETED", "CLOSED"):
            st, d = http(b, f"/api/actions/{aid}/status", "POST", {"status": s, "actor": "tech.ravi"})
            self.assertEqual(st, 200)

        # 8. closed WITHOUT verification must not count as resolved
        self.assertEqual(d["resolution"]["code"], "CLOSED_UNVERIFIED")
        st, ov = http(b, "/api/overview")
        self.assertEqual(ov["corrective_actions"]["workbench_closed_unverified"], 1)
        self.assertEqual(ov["findings_by_resolution"].get("VERIFIED_RESOLVED", 0), 0)
        self.assertEqual(http(b, f"/api/actions/{aid}/verify", "POST", {"verified_by": "tech.ravi", "method": "inspection", "evidence_text": "self check of the switch"})[0], 400)
        st, d = http(b, f"/api/actions/{aid}/verify", "POST", {"verified_by": "sup.anita", "method": "functional test", "evidence_text": "Opened guard 10x with machine running; E-stop chain tripped each time", "evidence_ref": "WO-4471"})
        self.assertEqual(d["resolution"]["code"], "VERIFIED_RESOLVED")
        st, ov = http(b, "/api/overview")
        self.assertEqual(ov["findings_by_resolution"]["VERIFIED_RESOLVED"], 1)

        # 9. re-run: identical digest, no duplicate findings, human work preserved
        con = store.connect(self.app.db)
        n_before = con.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        con.close()
        st, rr = http(b, "/api/rerun", "POST", {})
        self.assertTrue(rr["identical_to_previous"])
        con = store.connect(self.app.db)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM findings").fetchone()[0], n_before)
        self.assertEqual(con.execute("SELECT COUNT(DISTINCT finding_id) FROM findings").fetchone()[0], n_before)
        self.assertEqual(con.execute("SELECT COUNT(*) FROM findings WHERE active=0").fetchone()[0], 0)
        con.close()
        st, d2 = http(b, f"/api/findings/{fid}")
        self.assertEqual((d2["review"]["review_status"], d2["resolution"]["code"], len(d2["actions"])), ("UNDER_REVIEW", "VERIFIED_RESOLVED", 1))
        self.assertEqual(d2["evidence"], d["evidence"])
        r3 = analysis.run_analysis(self.out, self.feed, self.mapping, store_result=False)   # same code path, separate process-like run
        self.assertEqual(r3["digest"], rr["digest"])

        # 10. export is consistent with stored data
        st, zb = http(b, f"/api/findings/{fid}/export")
        z = zipfile.ZipFile(io.BytesIO(zb))
        names = {n.split("/", 1)[1] for n in z.namelist()}
        self.assertEqual(names, {"investigation_summary.md", "evidence.csv", "finding.json", "risk_factors.json", "actions.csv", "manifest.json"})
        read = lambda n: z.read(f"{fid}/{n}").decode()
        ev_rows = list(csv.DictReader(io.StringIO(read("evidence.csv"))))
        self.assertEqual([r["record_id"] for r in ev_rows], [e["record_id"] for e in d2["evidence"]])
        md = read("investigation_summary.md")
        for needle in (fid, d2["severity"], d2["rule_id"], "ADVISORY", "WA-", "sup.anita", "Opened guard 10x"):
            self.assertIn(needle, md)
        man = json.loads(read("manifest.json"))
        for n, h in man["sha256"].items():
            self.assertEqual(hashlib.sha256(read(n).encode()).hexdigest(), h)
        self.assertEqual(man["digest"], rr["digest"])

    def test_05_dashboard_and_error_handling(self):
        st, html = http(self.base, "/")
        self.assertEqual(st, 200); self.assertIn(b"Factory Safety Investigation Workbench", html)
        self.assertEqual(http(self.base, "/api/findings/F-NOPE-00000000")[0], 404)
        self.assertEqual(http(self.base, "/api/machines/M999")[0], 404)
        st, m = http(self.base, "/api/machines?plant=P1&sort=risk")
        self.assertTrue(all(x["plant_id"] == "P1" for x in m)); self.assertEqual([x["risk_score"] for x in m], sorted((x["risk_score"] for x in m), reverse=True))
        st, f = http(self.base, "/api/findings?date_from=2030-01-01")
        self.assertEqual(f["total"], 0)
        st, f = http(self.base, "/api/findings?machine=M001&severity=CRITICAL")
        self.assertTrue(all(x["machine_id"] == "M001" and x["severity"] == "CRITICAL" for x in f["items"]))


class Reproducibility(unittest.TestCase):
    def test_same_seed_same_files_and_pipeline_runs(self):
        a, b = tempfile.mkdtemp(), tempfile.mkdtemp()
        for d in (a, b):
            P.step_generate(d, C.PROFILES["starter"], C.DEFAULT_SEED)
        from fss import exporters as X
        self.assertEqual(X.checksums(a), X.checksums(b))
        r1 = analysis.run_analysis(a, store_result=False); r2 = analysis.run_analysis(b, store_result=False)
        self.assertEqual(r1["digest"], r2["digest"])
        self.assertEqual([f["finding_id"] for f in r1["findings"]], [f["finding_id"] for f in r2["findings"]])


if __name__ == "__main__":
    unittest.main()

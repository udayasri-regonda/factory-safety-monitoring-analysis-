import os, sys, sqlite3, tempfile, unittest
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))
from fss import config as C, pipeline as P, exporters as X
from fss.generator import generate


class PipelineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.mkdtemp()
        cls.res = P.run_all(cls.tmp, "starter", 42, log=lambda *_: None)

    def test_structural_validation_passes(self):
        self.assertTrue(self.res["validation_ok"])

    def test_detector_finds_all_injected_anomalies(self):
        o = self.res["evaluation"]
        self.assertEqual(o["recall"], 1.0)
        self.assertEqual(o["false_positives"], 0)

    def test_reproducible(self):
        self.assertTrue(self.res["reproducible"])

    def test_scale_exact(self):
        t, *_ = generate(C.PROFILES["starter"], 42)
        self.assertEqual(len(t["alarm_events"]), 2000)

    def test_append_only_triggers(self):
        con = sqlite3.connect(os.path.join(self.tmp, "db", "factory_safety.sqlite"))
        with self.assertRaises(sqlite3.DatabaseError):
            con.execute("DELETE FROM alarm_events")
        with self.assertRaises(sqlite3.DatabaseError):
            con.execute("UPDATE acknowledgements SET ack_method='HMI'")

    def test_seed_sql_loads(self):
        con = sqlite3.connect(":memory:")
        con.executescript(X.schema_sql())
        con.executescript(open(os.path.join(self.tmp, "sql", "seed_data.sql")).read())
        self.assertEqual(con.execute("select count(*) from alarm_events").fetchone()[0], 2000)
        self.assertEqual(con.execute("pragma foreign_key_check").fetchall(), [])

if __name__ == "__main__":
    unittest.main()

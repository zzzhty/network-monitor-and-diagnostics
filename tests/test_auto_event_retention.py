"""Temporary SQLite databases and mocked auto evaluators; no live sources."""
import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import nmd_monitor as m
import egress_sources as e


class AutoEventRetentionTests(unittest.TestCase):
    def setUp(self):
        temp = tempfile.TemporaryDirectory()
        self.addCleanup(temp.cleanup)
        self.path = Path(temp.name).resolve() / "state"
        self.store = m.Store(self.path, {"retention_hours": 24, "max_samples": 100})
        self.addCleanup(lambda: self.store.close())

    def event(self, timestamp, kind="auto_switch", detail=None):
        with patch.object(m.time, "time", return_value=timestamp):
            self.store.auto_event(kind, detail or {})

    def test_expired_and_excess_events_share_sample_retention(self):
        self.event(1)
        for index in range(110): self.event(100000 + index)
        self.store.record([], now=100200)
        rows = self.store.db.execute("SELECT id,ts FROM auto_events ORDER BY id").fetchall()
        self.assertEqual(len(rows), 100)
        self.assertEqual(rows[0][0], 12)
        self.assertGreaterEqual(rows[0][1], 100000)

    def test_ids_survive_complete_cleanup_and_database_reopen(self):
        self.event(1)
        before = self.store.db.execute("SELECT MAX(id) FROM auto_events").fetchone()[0]
        self.store.record([], now=100000)
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM auto_events").fetchone()[0], 0)
        self.store.close()
        self.store = m.Store(self.path, {"retention_hours": 24, "max_samples": 100})
        self.event(100001)
        after = self.store.db.execute("SELECT MAX(id) FROM auto_events").fetchone()[0]
        self.assertGreater(after, before)

    def test_legacy_database_high_water_mark_is_preserved(self):
        self.store.db.execute("INSERT INTO auto_events VALUES(250,1,'auto_switch','{}')")
        self.store.record([], now=100000)
        self.event(100001)
        self.assertGreater(self.store.db.execute("SELECT MAX(id) FROM auto_events").fetchone()[0], 250)

    def cycle(self, callback):
        with patch.object(e, "auto_evaluate", callback):
            m.run_auto_cycle(self.store, self.path.parent / "mock-sources", {"interval_seconds": 30})

    def test_repeated_faults_are_rate_limited_and_recovery_rearms(self):
        def unreachable(directory, runtime, emit):
            emit("controller_unreachable", {})
            return {"target": "primary"}
        with patch.object(m.time, "time", return_value=100000):
            for _ in range(10): self.cycle(unreachable)
            self.assertEqual(self.store.db.execute("SELECT count(*) FROM auto_events").fetchone()[0], 1)
            self.cycle(lambda directory, runtime, emit: {"target": "primary"})
            self.cycle(unreachable)
            self.assertEqual(self.store.db.execute("SELECT count(*) FROM auto_events").fetchone()[0], 2)
        with patch.object(m.time, "time", return_value=100601): self.cycle(unreachable)
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM auto_events").fetchone()[0], 3)

    def test_repeated_unexpected_errors_are_bounded_and_cleanup_applies(self):
        def broken(*args): raise RuntimeError("synthetic")
        with patch.object(m.time, "time", return_value=100000):
            for _ in range(10): self.cycle(broken)
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM auto_events").fetchone()[0], 1)
        self.store.record([], now=200000)
        self.assertEqual(self.store.db.execute("SELECT count(*) FROM auto_events").fetchone()[0], 0)

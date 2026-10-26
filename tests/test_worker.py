"""Tests for core/worker.py: the brain.rules fallback and the per-pass logging."""
from __future__ import annotations

import contextlib
import io
import sqlite3
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from common import db
from core import worker
from fixtures.load_fixtures import read_events
from tests.fake_rules import fake_behavior_hits


class LoadBehaviorHitsTests(unittest.TestCase):
    def test_missing_brain_rules_falls_back_to_no_hits_and_warns_once(self) -> None:
        output = io.StringIO()
        with mock.patch.dict(sys.modules, {"brain.rules": None}):  # None makes the import fail
            with contextlib.redirect_stdout(output):
                hits_fn = worker.load_behavior_hits()
        self.assertEqual(hits_fn({"source_ip": "1.2.3.4"}, {"allowed_source_ips": []}), [])
        warnings = [line for line in output.getvalue().splitlines() if "brain.rules" in line]
        self.assertEqual(len(warnings), 1)

    def test_uses_brain_rules_when_present(self) -> None:
        fake_module = mock.Mock(behavior_hits=fake_behavior_hits)
        output = io.StringIO()
        with mock.patch.dict(sys.modules, {"brain.rules": fake_module}):
            with contextlib.redirect_stdout(output):
                hits_fn = worker.load_behavior_hits()
        self.assertIs(hits_fn, fake_behavior_hits)
        self.assertEqual(output.getvalue(), "")


class RunOnceTests(unittest.TestCase):
    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        self.conn = db.connect(Path(tmp.name) / "test.db")
        self.addCleanup(self.conn.close)
        db.init(self.conn)
        self.baselines = db.load_json("baselines.json")

    def run_once(self) -> tuple[int, list[str]]:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            count = worker.run_once(self.conn, fake_behavior_hits, self.baselines)
        return count, output.getvalue().splitlines()

    def load(self, *names: str) -> None:
        for event in read_events(list(names)):
            db.insert_event(self.conn, event)
        self.conn.commit()

    def test_logs_one_line_per_opened_incident(self) -> None:
        self.load("scenario1", "scenario2")
        count, lines = self.run_once()
        self.assertEqual(count, 8)
        self.assertEqual(len(lines), 2)
        self.assertIn("INC-001 opened", lines[0])
        self.assertIn("INC-002 opened", lines[1])
        self.assertIn("score=95", lines[0])
        self.assertIn("critical", lines[0])

    def test_logs_updated_when_an_existing_incident_grows(self) -> None:
        self.load("scenario1")
        self.run_once()
        # A new event for the same bait joins the existing incident.
        late = dict(next(e for e in read_events(["scenario1"]) if e["event_id"] == "evt_s1000002"))
        late["event_id"] = "evt_late0001"
        late["ts"] = "2026-10-25T10:05:00Z"
        db.insert_event(self.conn, late)
        self.conn.commit()
        count, lines = self.run_once()
        self.assertEqual(count, 1)
        self.assertEqual(len(lines), 1)
        self.assertIn("INC-001 updated", lines[0])

    def test_logs_nothing_when_there_is_nothing_to_do(self) -> None:
        count, lines = self.run_once()
        self.assertEqual((count, lines), (0, []))

    def test_events_without_incident_change_log_nothing(self) -> None:
        self.load("normal")
        count, lines = self.run_once()
        self.assertEqual((count, lines), (2, []))


class StopLoop(Exception):
    pass


class MainLoopTests(unittest.TestCase):
    def test_database_error_rolls_back_the_open_transaction(self) -> None:
        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        conn = db.connect(Path(tmp.name) / "test.db")
        self.addCleanup(conn.close)
        db.init(conn)

        def failing_run_once(conn, behavior_hits_fn, baselines):
            conn.execute("UPDATE events SET processed = 1")  # opens a write transaction
            raise sqlite3.OperationalError("database is locked")

        def stop(seconds: float) -> None:
            raise StopLoop

        with (
            mock.patch.object(worker.db, "connect", return_value=conn),
            mock.patch.object(worker, "run_once", failing_run_once),
            contextlib.redirect_stdout(io.StringIO()),
        ):
            with self.assertRaises(StopLoop):
                worker.main(sleep=stop)
        self.assertFalse(conn.in_transaction)


if __name__ == "__main__":
    unittest.main()

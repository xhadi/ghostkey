"""Shared test helpers for the brain tests: a temp DB plus the REAL core run over fixtures."""
from __future__ import annotations

import json

from brain.rules import behavior_hits
from core.engine import load_incident, process_pending
from tests.test_core import CoreTestCase


class BrainTestCase(CoreTestCase):
    """CoreTestCase, but core runs with the real brain.rules.behavior_hits."""

    def run_core(self) -> int:
        return process_pending(self.conn, behavior_hits, self.baselines)

    def incident(self, incident_id: str) -> dict:
        """The incidents row with its JSON columns decoded."""
        row = self.conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone()
        return load_incident(row)

    def events_of(self, incident_id: str) -> list[dict]:
        """The incident's events, ordered by ts then event_id."""
        rows = self.conn.execute(
            "SELECT * FROM events WHERE incident_id = ? ORDER BY ts, event_id", (incident_id,)
        ).fetchall()
        return [dict(row) for row in rows]

    def stored_analyses(self) -> dict[str, dict]:
        """incident_id -> analyses row, with body decoded from JSON."""
        rows = self.conn.execute("SELECT * FROM analyses ORDER BY incident_id").fetchall()
        result = {}
        for row in rows:
            analysis = dict(row)
            analysis["body"] = json.loads(analysis["body"])
            result[analysis["incident_id"]] = analysis
        return result

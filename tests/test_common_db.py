"""Tests for common/db.py: schema init, the actions column migration and the mode check."""
from __future__ import annotations

import sqlite3
import tempfile
import unittest
from pathlib import Path

from common import db

OLD_INCIDENTS_DDL = "CREATE TABLE incidents (incident_id TEXT PRIMARY KEY)"
OLD_ACTIONS_DDL = """
CREATE TABLE actions (
  action_id    INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id  TEXT NOT NULL REFERENCES incidents(incident_id),
  ts           TEXT NOT NULL,
  kind         TEXT NOT NULL CHECK (kind IN ('disable_bait','revoke_credential','block_publish','notify')),
  target       TEXT,
  tier         TEXT NOT NULL CHECK (tier IN ('auto','approval')),
  status       TEXT NOT NULL CHECK (status IN ('done','pending','approved','rejected')),
  decided_by   TEXT,
  decided_ts   TEXT
)
"""


def action_columns(conn: sqlite3.Connection) -> list[str]:
    return [row["name"] for row in conn.execute("PRAGMA table_info(actions)")]


class DbInitTestCase(unittest.TestCase):
    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.conn = db.connect(Path(self.tmp.name) / "test.db")
        self.addCleanup(self.conn.close)

    def test_init_adds_new_action_columns_to_old_db(self) -> None:
        self.conn.execute(OLD_INCIDENTS_DDL)
        self.conn.execute(OLD_ACTIONS_DDL)
        self.conn.commit()
        self.assertNotIn("scope_ip", action_columns(self.conn))

        db.init(self.conn)

        self.assertTrue({"scope_ip", "mode"} <= set(action_columns(self.conn)))

    def test_init_twice_is_harmless(self) -> None:
        db.init(self.conn)
        db.init(self.conn)
        columns = action_columns(self.conn)
        self.assertEqual(1, columns.count("scope_ip"))
        self.assertEqual(1, columns.count("mode"))

    def test_mode_check_rejects_unknown_value(self) -> None:
        db.init(self.conn)
        self.conn.execute("INSERT INTO incidents (incident_id, created_ts, updated_ts, signal_kind, confidence,"
                          " score, severity, status) VALUES ('INC-001','t','t','bait','high',60,'medium','open')")
        with self.assertRaises(sqlite3.IntegrityError):
            self.conn.execute(
                "INSERT INTO actions (incident_id, ts, kind, tier, status, mode)"
                " VALUES ('INC-001','t','revoke_credential','approval','approved','nuke')"
            )


if __name__ == "__main__":
    unittest.main()

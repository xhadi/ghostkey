"""Read-side helpers for the dashboard (no streamlit import, so tests can run anywhere).

The dashboard is read-only, with ONE exception: decide_action() updates
actions.status / decided_by / decided_ts for approval-tier actions that are still pending.
"""
from __future__ import annotations

import json
import sqlite3

from common import db

# Columns of incidents that hold JSON text; we decode them for the caller.
INCIDENT_JSON_COLUMNS = ("source_ips", "token_ids", "stages", "rules_hit")


def open_db() -> sqlite3.Connection:
    """Open the shared DB. init() is harmless (CREATE IF NOT EXISTS) and avoids a crash on a fresh volume."""
    conn = db.connect()
    db.init(conn)
    return conn


def _decode_incident(row: sqlite3.Row) -> dict:
    incident = dict(row)
    for column in INCIDENT_JSON_COLUMNS:
        incident[column] = json.loads(incident[column] or "[]")
    return incident


def list_incidents(conn: sqlite3.Connection) -> list[dict]:
    """All incidents, most recently updated first (id breaks ties so the order is stable)."""
    rows = conn.execute("SELECT * FROM incidents ORDER BY updated_ts DESC, incident_id DESC").fetchall()
    return [_decode_incident(row) for row in rows]


def list_events(conn: sqlite3.Connection, incident_id: str) -> list[dict]:
    """Events of one incident in time order (oldest first)."""
    rows = conn.execute(
        "SELECT * FROM events WHERE incident_id = ? ORDER BY ts ASC, rowid ASC", (incident_id,)
    ).fetchall()
    return [dict(row) for row in rows]


def get_analysis(conn: sqlite3.Connection, incident_id: str) -> dict | None:
    """The analysis row with its JSON body decoded, or None if the brain has not written one yet."""
    row = conn.execute("SELECT * FROM analyses WHERE incident_id = ?", (incident_id,)).fetchone()
    if row is None:
        return None
    analysis = dict(row)
    analysis["body"] = json.loads(analysis["body"])
    return analysis


def list_actions(conn: sqlite3.Connection, incident_id: str) -> list[dict]:
    rows = conn.execute(
        "SELECT * FROM actions WHERE incident_id = ? ORDER BY action_id ASC", (incident_id,)
    ).fetchall()
    return [dict(row) for row in rows]


def pending_approval_counts(conn: sqlite3.Connection) -> dict[str, int]:
    """incident_id -> number of approval actions still waiting (used for the badge in the rail)."""
    rows = conn.execute(
        "SELECT incident_id, COUNT(*) AS n FROM actions "
        "WHERE tier = 'approval' AND status = 'pending' GROUP BY incident_id"
    ).fetchall()
    return {row["incident_id"]: row["n"] for row in rows}


def traffic_counts(conn: sqlite3.Connection) -> dict[str, int]:
    """Numbers for the traffic strip in the header."""
    def one(sql: str) -> int:
        return conn.execute(sql).fetchone()[0]

    return {
        "events": one("SELECT COUNT(*) FROM events"),
        "decoy": one("SELECT COUNT(*) FROM events WHERE routed_to = 'decoy'"),
        "real": one("SELECT COUNT(*) FROM events WHERE routed_to = 'real'"),
        "blocked": one("SELECT COUNT(*) FROM events WHERE routed_to = 'blocked'"),
        "open_incidents": one("SELECT COUNT(*) FROM incidents WHERE status != 'closed'"),
        "unlinked_signals": one("SELECT COUNT(*) FROM signals WHERE incident_id IS NULL"),
    }


def decide_action(conn: sqlite3.Connection, action_id: int, decision: str, decided_by: str) -> bool:
    """Approve or reject a pending approval-tier action. Returns True if a row changed.

    The WHERE clause is the guard: a decided action, or an auto action, matches no row.
    """
    new_status = {"approve": "approved", "reject": "rejected"}.get(decision)
    if new_status is None:
        raise ValueError(f"decision must be 'approve' or 'reject', got {decision!r}")
    reviewer = decided_by.strip() or "analyst"
    cursor = conn.execute(
        "UPDATE actions SET status = ?, decided_by = ?, decided_ts = ? "
        "WHERE action_id = ? AND tier = 'approval' AND status = 'pending'",
        (new_status, reviewer, db.now_iso(), action_id),
    )
    conn.commit()
    return cursor.rowcount == 1

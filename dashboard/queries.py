"""Read-side helpers for the dashboard (no streamlit import, so tests can run anywhere).

The dashboard is read-only, with ONE exception: decide_action() updates
actions.status / decided_by / decided_ts (and mode, for Block / Divert) on approval-tier
actions that are still pending.
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


def triage_funnel(conn: sqlite3.Connection) -> dict[str, int]:
    """Counts for the triage funnel, per SESSION, so it always agrees with the sessions table.

    A request counts with its session: in_incidents if any event of the session is in an incident,
    else flagged if the session has signals, else passed. passed + flagged + in_incidents == requests.
    (Core leaves a repeated rule hit without incident_id and signal, so judging single events would
    call an attacker's follow-up request "passed silently".)
    """
    def one(sql: str) -> int:
        return conn.execute(sql).fetchone()[0]

    funnel = {"requests": 0, "passed": 0, "flagged": 0, "in_incidents": 0}
    for session in list_sessions(conn):
        funnel["requests"] += session["requests"]
        if session["incident_id"]:
            funnel["in_incidents"] += session["requests"]
        elif session["points"] > 0:
            funnel["flagged"] += session["requests"]
        else:
            funnel["passed"] += session["requests"]
    funnel["incidents"] = one("SELECT COUNT(*) FROM incidents")
    funnel["analyzed"] = one("SELECT COUNT(*) FROM incidents WHERE incident_id IN (SELECT incident_id FROM analyses)")
    funnel["analyzed_llm"] = one("SELECT COUNT(*) FROM analyses WHERE source = 'llm' AND valid = 1")
    return funnel


def list_sessions(conn: sqlite3.Connection) -> list[dict]:
    """One row per session_id over all events.

    Order: sessions in an incident first, then flagged ones (points > 0), then the rest;
    newest last_ts first inside each group.
    """
    rows = conn.execute(
        "SELECT e.session_id, e.source_ip, e.bait_id, e.credential_id, e.token_kind, e.ts, e.incident_id, "
        "COALESCE((SELECT SUM(s.points) FROM signals s WHERE s.event_id = e.event_id), 0) AS points "
        "FROM events e ORDER BY e.ts ASC, e.rowid ASC"
    ).fetchall()
    sessions: dict[str, dict] = {}
    for row in rows:
        session = sessions.get(row["session_id"])
        if session is None:
            # Rows come oldest first, so the first row of a session is its first event.
            session = sessions[row["session_id"]] = {
                "session_id": row["session_id"],
                "source_ip": row["source_ip"],
                "token": row["bait_id"] or row["credential_id"] or "anonymous",
                "token_kind": row["token_kind"],
                "requests": 0,
                "points": 0,
                "incident_id": None,
                "last_ts": row["ts"],
            }
        session["requests"] += 1
        session["points"] += row["points"]
        session["incident_id"] = session["incident_id"] or row["incident_id"]
        session["last_ts"] = max(session["last_ts"], row["ts"])

    def group(session: dict) -> int:
        if session["incident_id"]:
            return 0
        return 1 if session["points"] > 0 else 2

    # Two stable sorts: newest first, then by group.
    ordered = sorted(sessions.values(), key=lambda s: s["last_ts"], reverse=True)
    return sorted(ordered, key=group)


# decision -> (new status, new mode, extra WHERE condition). The condition is the guard that keeps
# each decision on the kind of action it fits; all of them also need tier = 'approval' AND status = 'pending'.
DECISION_RULES = {
    "block": ("approved", "block", "kind = 'revoke_credential' AND scope_ip IS NOT NULL"),
    "divert": ("approved", "divert", "kind = 'revoke_credential' AND scope_ip IS NOT NULL"),
    "approve": ("approved", None, "kind != 'revoke_credential'"),
    "reject": ("rejected", None, "1 = 1"),
}


def decide_action(conn: sqlite3.Connection, action_id: int, decision: str, decided_by: str) -> bool:
    """Decide a pending approval-tier action. Returns True if a row changed.

    decision is block | divert | reject | approve. Block and divert set mode (the gateway enforces
    only approved rows that have a mode) and fit only a revoke_credential with a scope_ip.
    approve fits every other kind. The WHERE clause is the guard: a decided action, an auto action
    or a decision that does not fit the action matches no row.
    """
    rule = DECISION_RULES.get(decision)
    if rule is None:
        raise ValueError(f"decision must be one of {sorted(DECISION_RULES)}, got {decision!r}")
    new_status, new_mode, fits = rule
    reviewer = decided_by.strip() or "analyst"
    cursor = conn.execute(
        "UPDATE actions SET status = ?, mode = ?, decided_by = ?, decided_ts = ? "
        f"WHERE action_id = ? AND tier = 'approval' AND status = 'pending' AND {fits}",
        (new_status, new_mode, reviewer, db.now_iso(), action_id),
    )
    conn.commit()
    return cursor.rowcount == 1


# mode -> the routed_to value the gateway writes for a request it contained.
MODE_ROUTE = {"block": "blocked", "divert": "decoy"}


def containment_effect(conn: sqlite3.Connection, action: dict) -> int:
    """How many requests the gateway really contained for an approved Block / Divert.

    Counts events of that credential from that IP, routed as the mode says, at or after the decision.
    Returns 0 for anything that is not an approved revoke_credential with a mode and an IP.
    """
    route = MODE_ROUTE.get(action.get("mode") or "")
    if (action["kind"] != "revoke_credential" or action["status"] != "approved"
            or route is None or not action.get("scope_ip") or not action.get("decided_ts")):
        return 0
    return conn.execute(
        "SELECT COUNT(*) FROM events WHERE credential_id = ? AND source_ip = ? AND routed_to = ? AND ts >= ?",
        (action["target"], action["scope_ip"], route, action["decided_ts"]),
    ).fetchone()[0]

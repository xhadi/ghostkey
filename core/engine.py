"""Correlation, scoring and response actions for events.

Flow for each unprocessed event (see CLAUDE.md "Correlation" and "Scoring"):
  1. find an open incident the event joins (same token, or same IP within 30 minutes)
  2. work out the rule hits (bait rules here, behavior rules from brain/rules.py)
  3. join the incident, open a new one, or leave the event unattached
An incident's score, rules_hit, ips, tokens and stages are always recomputed from its
signals and events (refresh_incident), so the table can never drift from the evidence.
"""
from __future__ import annotations

import json
import sqlite3
import traceback
from datetime import timedelta
from typing import Callable

from common import db
from core import scoring

BehaviorHitsFn = Callable[[dict, "dict | None"], "list[dict]"]

NOTIFY_TARGET = "security-team"


# ---------------------------------------------------------------- small helpers

def event_token_id(event: dict) -> str | None:
    """The token an event used: its bait_id or its credential_id."""
    return event["bait_id"] or event["credential_id"]


def load_incident(row: sqlite3.Row) -> dict:
    """Turn an incidents row into a dict with the JSON columns decoded."""
    incident = dict(row)
    for key in ("source_ips", "token_ids", "stages", "rules_hit"):
        incident[key] = json.loads(incident[key])
    return incident


def next_incident_id(conn: sqlite3.Connection) -> str:
    """INC-001, INC-002, ... one more than the highest existing number."""
    rows = conn.execute("SELECT incident_id FROM incidents").fetchall()
    numbers = [int(row["incident_id"].split("-")[1]) for row in rows]
    return f"INC-{max(numbers, default=0) + 1:03d}"


def window_start(ts: str) -> str:
    """The start of the 30-minute window that ends at `ts` (ISO string, ends in Z)."""
    start = db.parse_iso(ts) - timedelta(minutes=scoring.WINDOW_MINUTES)
    return start.strftime("%Y-%m-%dT%H:%M:%SZ")


def counted_hits(hits: list[dict], incident: dict) -> list[dict]:
    """Drop hits whose rule the incident already counted (each rule counts once)."""
    seen = {hit["rule"] for hit in incident["rules_hit"]}
    return [hit for hit in hits if hit["rule"] not in seen]


# ---------------------------------------------------------------- writing rows

def insert_signal(conn: sqlite3.Connection, event: dict, hit: dict, incident_id: str | None) -> None:
    conn.execute(
        "INSERT INTO signals (ts, event_id, token_id, rule, points, incident_id) VALUES (?,?,?,?,?,?)",
        (event["ts"], event["event_id"], event_token_id(event), hit["rule"], hit["points"], incident_id),
    )


def insert_action(conn: sqlite3.Connection, incident_id: str, ts: str, kind: str,
                  target: str, tier: str, status: str) -> None:
    conn.execute(
        "INSERT INTO actions (incident_id, ts, kind, target, tier, status) VALUES (?,?,?,?,?,?)",
        (incident_id, ts, kind, target, tier, status),
    )


def ensure_disable_bait(conn: sqlite3.Connection, incident_id: str, event: dict) -> None:
    """Auto action: disable the bait the event used, once per incident."""
    bait_id = event["bait_id"]
    existing = conn.execute(
        "SELECT 1 FROM actions WHERE incident_id = ? AND kind = 'disable_bait' AND target = ?",
        (incident_id, bait_id),
    ).fetchone()
    if existing is None:
        insert_action(conn, incident_id, event["ts"], "disable_bait", bait_id, "auto", "done")


def create_incident(conn: sqlite3.Connection, signal_kind: str, confidence: str,
                    status: str, created_ts: str) -> str:
    """Insert an empty incident; refresh_incident fills in the rest."""
    incident_id = next_incident_id(conn)
    conn.execute(
        "INSERT INTO incidents (incident_id, created_ts, updated_ts, signal_kind, confidence,"
        " score, severity, status) VALUES (?,?,?,?,?,?,?,?)",
        (incident_id, created_ts, created_ts, signal_kind, confidence, 0, "low", status),
    )
    return incident_id


def attach_event(conn: sqlite3.Connection, event_id: str, incident_id: str) -> None:
    conn.execute("UPDATE events SET incident_id = ? WHERE event_id = ?", (incident_id, event_id))


def refresh_incident(conn: sqlite3.Connection, incident_id: str) -> None:
    """Recompute rules_hit/score/severity from signals and ips/tokens/stages/updated_ts from events."""
    signals = conn.execute(
        "SELECT rule, points, event_id FROM signals WHERE incident_id = ? ORDER BY ts, signal_id",
        (incident_id,),
    ).fetchall()
    rules_hit = [{"rule": s["rule"], "points": s["points"], "event_id": s["event_id"]} for s in signals]
    score = sum(hit["points"] for hit in rules_hit)

    events = conn.execute(
        "SELECT ts, source_ip, bait_id, credential_id, stage FROM events"
        " WHERE incident_id = ? ORDER BY ts, event_id",
        (incident_id,),
    ).fetchall()
    source_ips = list(dict.fromkeys(e["source_ip"] for e in events))
    token_ids = list(dict.fromkeys(t for e in events if (t := e["bait_id"] or e["credential_id"])))
    stages = scoring.order_stages([e["stage"] for e in events])
    updated_ts = events[-1]["ts"]

    conn.execute(
        "UPDATE incidents SET updated_ts = ?, score = ?, severity = ?, source_ips = ?,"
        " token_ids = ?, stages = ?, rules_hit = ? WHERE incident_id = ?",
        (updated_ts, score, scoring.severity(score), json.dumps(source_ips), json.dumps(token_ids),
         json.dumps(stages), json.dumps(rules_hit), incident_id),
    )


# ---------------------------------------------------------------- finding an incident

def find_incident(conn: sqlite3.Connection, event: dict) -> dict | None:
    """The open incident this event joins, or None. Latest-updated wins if several match."""
    rows = conn.execute("SELECT * FROM incidents WHERE status != 'closed'").fetchall()
    event_time = db.parse_iso(event["ts"])
    window = timedelta(minutes=scoring.WINDOW_MINUTES)
    token_id = event_token_id(event)
    matches = []
    for row in rows:
        incident = load_incident(row)
        same_token = token_id is not None and token_id in incident["token_ids"]
        same_ip_recently = (
            event["source_ip"] in incident["source_ips"]
            and event_time - db.parse_iso(incident["updated_ts"]) <= window
        )
        if same_token or same_ip_recently:
            matches.append(incident)
    if not matches:
        return None
    return max(matches, key=lambda inc: (inc["updated_ts"], inc["incident_id"]))


# ---------------------------------------------------------------- joining and opening

def join_incident(conn: sqlite3.Connection, incident: dict, event: dict, hits: list[dict]) -> None:
    """Attach the event to an existing incident and count its new hits."""
    incident_id = incident["incident_id"]
    for hit in counted_hits(hits, incident):
        insert_signal(conn, event, hit, incident_id)
    attach_event(conn, event["event_id"], incident_id)
    if event["token_kind"] == "bait":
        if incident["confidence"] != "high":
            conn.execute("UPDATE incidents SET confidence = 'high', status = 'open' WHERE incident_id = ?",
                         (incident_id,))
        ensure_disable_bait(conn, incident_id, event)
    refresh_incident(conn, incident_id)


def open_bait_incident(conn: sqlite3.Connection, event: dict) -> str:
    """A bait event with no incident to join opens a new high-confidence incident."""
    incident_id = create_incident(conn, "bait", "high", "open", event["ts"])
    for hit in scoring.bait_hits(event, None):
        insert_signal(conn, event, hit, incident_id)
    attach_event(conn, event["event_id"], incident_id)
    refresh_incident(conn, incident_id)
    insert_action(conn, incident_id, event["ts"], "notify", NOTIFY_TARGET, "auto", "done")
    ensure_disable_bait(conn, incident_id, event)
    return incident_id


def window_signals(conn: sqlite3.Connection, event: dict) -> list[sqlite3.Row]:
    """Unattached signals of the event's credential from the last 30 minutes."""
    return conn.execute(
        "SELECT * FROM signals WHERE incident_id IS NULL AND token_id = ? AND ts >= ?"
        " ORDER BY ts, signal_id",
        (event["credential_id"], window_start(event["ts"])),
    ).fetchall()


def open_behavior_incident(conn: sqlite3.Connection, event: dict, signals: list[sqlite3.Row]) -> str:
    """Open a needs_review incident and attach every event that counted toward it."""
    event_ids = {s["event_id"] for s in signals} | {event["event_id"]}
    created_ts = min([s["ts"] for s in signals] + [event["ts"]])
    incident_id = create_incident(conn, "behavior", "medium", "needs_review", created_ts)
    for signal in signals:
        conn.execute("UPDATE signals SET incident_id = ? WHERE signal_id = ?",
                     (incident_id, signal["signal_id"]))
    for event_id in event_ids:
        attach_event(conn, event_id, incident_id)
    refresh_incident(conn, incident_id)
    insert_action(conn, incident_id, event["ts"], "notify", NOTIFY_TARGET, "auto", "done")
    insert_action(conn, incident_id, event["ts"], "revoke_credential", event["credential_id"],
                  "approval", "pending")
    return incident_id


def count_behavior_hits(conn: sqlite3.Connection, event: dict, hits: list[dict]) -> None:
    """A real-token event with no incident: keep its new hits, open an incident at 60 points."""
    if not hits:
        return
    seen = {signal["rule"] for signal in window_signals(conn, event)}
    for hit in hits:
        if hit["rule"] not in seen:
            insert_signal(conn, event, hit, None)
            seen.add(hit["rule"])
    signals = window_signals(conn, event)
    if sum(signal["points"] for signal in signals) >= scoring.BEHAVIOR_THRESHOLD:
        open_behavior_incident(conn, event, signals)


def hits_for_event(event: dict, incident: dict | None,
                   behavior_hits_fn: BehaviorHitsFn, baselines: dict) -> list[dict]:
    """Raw rule hits for one event (before once-per-rule counting)."""
    if event["token_kind"] == "bait":
        return scoring.bait_hits(event, incident)
    if event["token_kind"] == "real":
        try:
            return behavior_hits_fn(event, baselines.get(event["credential_id"]))
        except Exception:  # a bug in brain.rules must not stop correlation
            print(f"core: WARNING behavior rules failed on {event['event_id']}, counting no hits", flush=True)
            traceback.print_exc()
            return []
    return []


# ---------------------------------------------------------------- main entry points

def process_event(conn: sqlite3.Connection, event: dict,
                  behavior_hits_fn: BehaviorHitsFn, baselines: dict) -> None:
    """Correlate and score one event. Marks it processed. The caller commits."""
    incident = find_incident(conn, event)
    hits = hits_for_event(event, incident, behavior_hits_fn, baselines)
    if incident is not None:
        join_incident(conn, incident, event, hits)
    elif event["token_kind"] == "bait":
        open_bait_incident(conn, event)
    elif event["token_kind"] == "real":
        count_behavior_hits(conn, event, hits)
    conn.execute("UPDATE events SET processed = 1 WHERE event_id = ?", (event["event_id"],))


def process_pending(conn: sqlite3.Connection, behavior_hits_fn: BehaviorHitsFn,
                    baselines: dict) -> int:
    """Process every unprocessed event in time order, one transaction per event.

    A database error rolls back and is raised (the worker retries next second).
    Any other error is a bug for this one event: roll back, mark it processed, keep going.
    """
    rows = conn.execute("SELECT * FROM events WHERE processed = 0 ORDER BY ts, event_id").fetchall()
    for row in rows:
        try:
            process_event(conn, dict(row), behavior_hits_fn, baselines)
            conn.commit()
        except sqlite3.Error:
            conn.rollback()
            raise
        except Exception:
            conn.rollback()
            skip_event(conn, row["event_id"])
    return len(rows)


def skip_event(conn: sqlite3.Connection, event_id: str) -> None:
    """Mark an event that crashed core as processed (left unattached), so later events still run."""
    print(f"core: ERROR skipped {event_id}, it crashed core:", flush=True)
    traceback.print_exc()
    conn.execute("UPDATE events SET processed = 1 WHERE event_id = ?", (event_id,))
    conn.commit()

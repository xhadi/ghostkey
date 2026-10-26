"""Brain worker: python -m brain.worker

Every 2 seconds, write an analysis for each incident that has none yet or whose event count changed.
The rules-only analysis is always built first. An optional LLM function may replace it, but only if
its answer passes brain/validate.py. Otherwise the rules-only analysis is stored (CLAUDE.md "Analyst output").
This worker writes the `analyses` table only.
"""
from __future__ import annotations

import copy
import json
import os
import sqlite3
import time
import traceback
from typing import Callable

from brain.analyst_rules import rules_analysis
from brain.validate import validate
from common import db

POLL_SECONDS = 2.0

# llm_fn(incident, events) -> analysis body (dict) or None. It is brain.llm.analyze.
LlmFn = Callable[[dict, "list[dict]"], "dict | None"]

NO_LLM_MESSAGE = "brain: no LLM, rules-only analysis"
LLM_SETTINGS = ("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY")


# ---------------------------------------------------------------- reading

def pending_incident_ids(conn: sqlite3.Connection) -> list[str]:
    """Incidents with no analysis, or whose analysis was based on a different number of events."""
    rows = conn.execute(
        "SELECT i.incident_id FROM incidents i"
        " LEFT JOIN analyses a ON a.incident_id = i.incident_id"
        " WHERE a.incident_id IS NULL"
        "    OR a.based_on_event_count != (SELECT COUNT(*) FROM events e WHERE e.incident_id = i.incident_id)"
        " ORDER BY i.incident_id"
    ).fetchall()
    return [row["incident_id"] for row in rows]


def load_incident(conn: sqlite3.Connection, incident_id: str) -> dict:
    """The incidents row as a dict, with the JSON columns decoded."""
    incident = dict(conn.execute("SELECT * FROM incidents WHERE incident_id = ?", (incident_id,)).fetchone())
    for key in ("source_ips", "token_ids", "stages", "rules_hit"):
        incident[key] = json.loads(incident[key])
    return incident


def load_events(conn: sqlite3.Connection, incident_id: str) -> list[dict]:
    """The incident's events, ordered by ts then event_id."""
    rows = conn.execute(
        "SELECT * FROM events WHERE incident_id = ? ORDER BY ts, event_id", (incident_id,)
    ).fetchall()
    return [dict(row) for row in rows]


# ---------------------------------------------------------------- choosing the body

def call_llm(llm_fn: LlmFn, incident: dict, events: list[dict], event_ids: set[str]) -> dict | None:
    """Ask the LLM for a body. Returns it only if valid. Any failure returns None (and is logged)."""
    incident_id = incident["incident_id"]
    try:
        body = llm_fn(copy.deepcopy(incident), copy.deepcopy(events))
    except Exception as error:  # the LLM must never stop the loop
        print(f"brain: LLM failed for {incident_id}, using rules: {error!r}", flush=True)
        return None
    if body is None:
        return None
    errors = validate(body, event_ids)
    if errors:
        print(f"brain: LLM analysis for {incident_id} rejected, using rules: {'; '.join(errors)}", flush=True)
        return None
    return body


def rules_body_for(incident: dict, events: list[dict]) -> tuple[dict, int]:
    """Return (rules body, valid). The rules analysis must always be valid; if not, it's a bug in brain/."""
    rules_body = rules_analysis(incident, events)
    rules_errors = validate(rules_body, {event["event_id"] for event in events})
    if rules_errors:
        print(f"brain: BUG rules analysis for {incident['incident_id']} is invalid: {'; '.join(rules_errors)}",
              flush=True)
    return rules_body, 0 if rules_errors else 1


# ---------------------------------------------------------------- writing

def label_of(body: dict) -> str:
    """The hypothesis label for the log line ('?' if the body is broken, which is a bug)."""
    hypothesis = body.get("hypothesis")
    return hypothesis.get("label", "?") if isinstance(hypothesis, dict) else "?"


def store_analysis(conn: sqlite3.Connection, incident_id: str, source: str, valid: int,
                   event_count: int, body: dict) -> None:
    """Insert or replace the one analyses row of the incident, then commit."""
    conn.execute(
        "INSERT OR REPLACE INTO analyses (incident_id, ts, source, valid, based_on_event_count, body)"
        " VALUES (?,?,?,?,?,?)",
        (incident_id, db.now_iso(), source, valid, event_count, json.dumps(body, ensure_ascii=False)),
    )
    conn.commit()


def analyze_incident(conn: sqlite3.Connection, incident_id: str, llm_fn: LlmFn | None) -> bool:
    """Analyze and store one incident. Returns False if it was skipped (no events, or a bug).

    The rules analysis is stored first, so the dashboard never waits for the LLM (a call can take a minute).
    A valid LLM answer then replaces it.
    """
    incident = load_incident(conn, incident_id)
    events = load_events(conn, incident_id)
    if not events:
        return False
    try:
        rules_body, valid = rules_body_for(incident, events)
    except Exception:  # a bug for this one incident must not stop the others
        print(f"brain: ERROR could not analyze {incident_id}:", flush=True)
        traceback.print_exc()
        return False
    store_analysis(conn, incident_id, "rules", valid, len(events), rules_body)
    source, body = "rules", rules_body
    if llm_fn is not None:
        llm_body = call_llm(llm_fn, incident, events, {event["event_id"] for event in events})
        if llm_body is not None:
            store_analysis(conn, incident_id, "llm", 1, len(events), llm_body)
            source, body = "llm", llm_body
    print(f"brain: {incident_id} analyzed source={source} label={label_of(body)}", flush=True)
    return True


def analyze_pending(conn: sqlite3.Connection, llm_fn: LlmFn | None) -> int:
    """Analyze every incident that needs it. Returns how many analyses were stored.

    A database error is raised (the loop retries on the next pass).
    """
    count = 0
    for incident_id in pending_incident_ids(conn):
        if analyze_incident(conn, incident_id, llm_fn):
            count += 1
    return count


# ---------------------------------------------------------------- process entry point

def load_llm() -> LlmFn | None:
    """Return brain.llm.analyze if the module exists and all LLM_* settings are set, else None."""
    missing = [name for name in LLM_SETTINGS if not os.environ.get(name, "").strip()]
    if missing:
        print(f"{NO_LLM_MESSAGE} (missing {', '.join(missing)})", flush=True)  # names only, never values
        return None
    try:
        from brain.llm import analyze
    except ImportError as error:
        print(f"{NO_LLM_MESSAGE} (brain.llm unavailable: {error})", flush=True)
        return None
    return analyze


def run_loop(conn: sqlite3.Connection, llm_fn: LlmFn | None,
             sleep: Callable[[float], None] = time.sleep) -> None:
    """Analyze pending incidents forever. A database error is printed and retried."""
    while True:
        try:
            analyze_pending(conn, llm_fn)
        except sqlite3.Error as error:  # for example "database is locked": try again next pass
            conn.rollback()  # end the failed transaction, or it keeps the write lock and blocks everyone
            print(f"brain: database error, will retry: {error}", flush=True)
        sleep(POLL_SECONDS)


def main() -> None:
    conn = db.connect()
    db.init(conn)
    llm_fn = load_llm()
    print(f"brain: worker started, db={db.DB_PATH}", flush=True)
    run_loop(conn, llm_fn)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("brain: worker stopped", flush=True)

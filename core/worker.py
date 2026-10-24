"""Core worker: python -m core.worker

Every second, correlate and score the events the gateway inserted (events.processed = 0).
"""
from __future__ import annotations

import sqlite3
import time
from typing import Callable

from common import db
from core.engine import BehaviorHitsFn, process_pending

POLL_SECONDS = 1.0


def load_behavior_hits() -> BehaviorHitsFn:
    """Use brain.rules.behavior_hits. If it is not written yet, warn once and return no hits."""
    try:
        from brain.rules import behavior_hits
    except ImportError:
        print("core: WARNING brain.rules not found, behavior rules are off (bait detection still works)",
              flush=True)
        return lambda event, baseline: []
    return behavior_hits


def snapshot_incidents(conn: sqlite3.Connection) -> dict[str, dict]:
    """incident_id -> the fields that change when an incident grows."""
    rows = conn.execute(
        "SELECT incident_id, signal_kind, updated_ts, score, severity, confidence, status FROM incidents"
    ).fetchall()
    return {row["incident_id"]: dict(row) for row in rows}


def log_changes(before: dict[str, dict], after: dict[str, dict]) -> None:
    """Print one line for each incident that was opened or updated."""
    for incident_id, now in after.items():
        if incident_id not in before:
            verb = "opened"
        elif before[incident_id] != now:
            verb = "updated"
        else:
            continue
        print(f"core: {incident_id} {verb} kind={now['signal_kind']} score={now['score']}"
              f" severity={now['severity']} confidence={now['confidence']} status={now['status']}",
              flush=True)


def run_once(conn: sqlite3.Connection, behavior_hits_fn: BehaviorHitsFn, baselines: dict) -> int:
    """One pass: process pending events and log incident changes. Returns events processed."""
    before = snapshot_incidents(conn)
    count = process_pending(conn, behavior_hits_fn, baselines)
    if count:
        log_changes(before, snapshot_incidents(conn))
    return count


def main(sleep: Callable[[float], None] = time.sleep) -> None:
    conn = db.connect()
    db.init(conn)
    baselines = db.load_json("baselines.json")
    behavior_hits_fn = load_behavior_hits()
    print(f"core: worker started, db={db.DB_PATH}", flush=True)
    while True:
        try:
            run_once(conn, behavior_hits_fn, baselines)
        except sqlite3.Error as error:  # for example "database is locked": try again next second
            print(f"core: database error, will retry: {error}", flush=True)
        sleep(POLL_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("core: worker stopped", flush=True)

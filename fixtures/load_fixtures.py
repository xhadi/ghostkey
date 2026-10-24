"""Load fixture events into the DB so core, brain and dashboard can work without the gateway.

Usage:
    python -m fixtures.load_fixtures --reset            # all fixtures
    python -m fixtures.load_fixtures --reset scenario1  # one file

Timestamps are shifted so the newest fixture event is "now" (gaps between events are kept),
which keeps the 30-minute correlation window realistic.
"""
from __future__ import annotations

import argparse
import json
from datetime import timedelta
from pathlib import Path

from common import db

FIXTURES_DIR = Path(__file__).resolve().parent
DEFAULT_FILES = ("normal", "scenario1", "scenario2")


def read_events(names: list[str]) -> list[dict]:
    events: list[dict] = []
    for name in names:
        path = FIXTURES_DIR / f"{name}.jsonl"
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                events.append(json.loads(line))
    return sorted(events, key=lambda e: e["ts"])


def shift_to_now(events: list[dict]) -> list[dict]:
    if not events:
        return events
    newest = db.parse_iso(events[-1]["ts"])
    delta = db.parse_iso(db.now_iso()) - newest
    for e in events:
        e["ts"] = (db.parse_iso(e["ts"]) + delta).strftime("%Y-%m-%dT%H:%M:%SZ")
    return events


def write_fake_core(conn, events: list[dict]) -> None:
    """DEVELOPMENT ONLY: write fixtures/expected_state.json as if core and brain already ran."""
    state = json.loads((FIXTURES_DIR / "expected_state.json").read_text(encoding="utf-8"))
    ts_by_id = {e["event_id"]: e["ts"] for e in events}
    loaded = set(ts_by_id)
    conn.execute("UPDATE events SET processed = 1")
    for inc in state["incidents"]:
        ids = [i for i in inc["events"] if i in loaded]
        if not ids:
            continue
        times = sorted(ts_by_id[i] for i in ids)
        conn.execute(
            "INSERT INTO incidents VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
            (inc["incident_id"], times[0], times[-1], inc["signal_kind"], inc["confidence"],
             inc["score"], inc["severity"], inc["status"], json.dumps(inc["source_ips"]),
             json.dumps(inc["token_ids"]), json.dumps(inc["stages"]), json.dumps(inc["rules_hit"])),
        )
        conn.executemany("UPDATE events SET incident_id = ? WHERE event_id = ?",
                         [(inc["incident_id"], i) for i in ids])
        for hit in inc["rules_hit"]:
            conn.execute(
                "INSERT INTO signals (ts, event_id, token_id, rule, points, incident_id) VALUES (?,?,?,?,?,?)",
                (ts_by_id[hit["event_id"]], hit["event_id"], None, hit["rule"], hit["points"], inc["incident_id"]),
            )
        for a in state["analyses"]:
            if a["incident_id"] == inc["incident_id"]:
                conn.execute("INSERT INTO analyses VALUES (?,?,?,?,?,?)",
                             (a["incident_id"], times[-1], a["source"], a["valid"], len(ids),
                              json.dumps(a["body"], ensure_ascii=False)))
        for act in state["actions"]:
            if act["incident_id"] == inc["incident_id"]:
                conn.execute(
                    "INSERT INTO actions (incident_id, ts, kind, target, tier, status) VALUES (?,?,?,?,?,?)",
                    (act["incident_id"], times[-1], act["kind"], act["target"], act["tier"], act["status"]),
                )


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("files", nargs="*", default=list(DEFAULT_FILES))
    parser.add_argument("--reset", action="store_true", help="delete all rows first")
    parser.add_argument("--fake-core", action="store_true",
                        help="DEV ONLY: also write the expected incidents/analyses/actions (for building the dashboard)")
    args = parser.parse_args()

    conn = db.connect()
    db.init(conn)
    if args.reset:
        db.reset(conn)
    events = shift_to_now(read_events(args.files))
    for e in events:
        db.insert_event(conn, e)
    if args.fake_core:
        write_fake_core(conn, events)
    conn.commit()
    print(f"loaded {len(events)} events into {db.DB_PATH}" + (" (+ fake core state)" if args.fake_core else ""))


if __name__ == "__main__":
    main()

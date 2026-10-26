"""Shared SQLite access for every Ghostkey process. Always use connect() from here."""
from __future__ import annotations

import json
import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DB_PATH = Path(os.environ.get("GHOSTKEY_DB", ROOT / "data" / "ghostkey.db"))
SCHEMA_PATH = ROOT / "contracts" / "schema.sql"

TABLES = ("actions", "analyses", "signals", "incidents", "events")

# Columns added to `actions` after the first release. Older DBs get them via ALTER TABLE.
ACTION_COLUMNS_ADDED_LATER = (
    ("scope_ip", "TEXT"),
    ("mode", "TEXT CHECK (mode IN ('block','divert'))"),
)


def connect(db_path: Path | str = DB_PATH) -> sqlite3.Connection:
    """Open the DB with WAL and a busy timeout so several processes can share it."""
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(db_path, timeout=5.0)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init(conn: sqlite3.Connection) -> None:
    """Create tables if they don't exist, and add newer columns to older tables."""
    conn.executescript(SCHEMA_PATH.read_text(encoding="utf-8"))
    _add_missing_action_columns(conn)
    conn.commit()


def _add_missing_action_columns(conn: sqlite3.Connection) -> None:
    """Add actions.scope_ip / actions.mode to a DB created before they existed."""
    existing = {row["name"] for row in conn.execute("PRAGMA table_info(actions)")}
    for name, definition in ACTION_COLUMNS_ADDED_LATER:
        if name in existing:
            continue
        try:
            conn.execute(f"ALTER TABLE actions ADD COLUMN {name} {definition}")
        except sqlite3.OperationalError as exc:
            # Several containers call init() at startup; another one may have won the race.
            if "duplicate column" not in str(exc).lower():
                raise


def reset(conn: sqlite3.Connection) -> None:
    """Delete all rows (keeps the tables). For demos and tests only."""
    for table in TABLES:
        conn.execute(f"DELETE FROM {table}")
    conn.execute("DELETE FROM sqlite_sequence")
    conn.commit()


def now_iso() -> str:
    """Current time as ISO 8601 UTC ending in Z."""
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_iso(ts: str) -> datetime:
    return datetime.strptime(ts, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)


def load_json(name: str):
    """Read a file from contracts/, e.g. load_json('baits.json')."""
    return json.loads((ROOT / "contracts" / name).read_text(encoding="utf-8"))


EVENT_COLUMNS = (
    "event_id", "ts", "session_id", "source_ip", "user_agent", "token_kind",
    "bait_id", "credential_id", "stage", "service", "method", "path", "action",
    "target", "status_code", "result", "routed_to", "incident_id", "processed",
)


def insert_event(conn: sqlite3.Connection, event: dict) -> None:
    """Insert one event dict (missing optional keys become NULL)."""
    row = {col: event.get(col) for col in EVENT_COLUMNS}
    if row["processed"] is None:
        row["processed"] = 0
    cols = ", ".join(EVENT_COLUMNS)
    marks = ", ".join(f":{c}" for c in EVENT_COLUMNS)
    conn.execute(f"INSERT INTO events ({cols}) VALUES ({marks})", row)

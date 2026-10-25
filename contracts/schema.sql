-- Ghostkey shared database. Owner of each table: see CLAUDE.md "Ownership".
-- All timestamps: ISO 8601 UTC strings ending in Z. JSON columns hold JSON text.

CREATE TABLE IF NOT EXISTS events (
  event_id       TEXT PRIMARY KEY,
  ts             TEXT NOT NULL,
  session_id     TEXT NOT NULL,
  source_ip      TEXT NOT NULL,
  user_agent     TEXT,
  token_kind     TEXT NOT NULL CHECK (token_kind IN ('bait','real','unknown','none')),
  bait_id        TEXT,
  credential_id  TEXT,
  stage          TEXT NOT NULL CHECK (stage IN ('source','build','publish','unknown')),
  service        TEXT NOT NULL CHECK (service IN ('git','npm')),
  method         TEXT NOT NULL,
  path           TEXT NOT NULL,
  action         TEXT NOT NULL,
  target         TEXT,
  status_code    INTEGER,
  result         TEXT CHECK (result IN ('ok','denied','error')),
  routed_to      TEXT NOT NULL CHECK (routed_to IN ('decoy','real','blocked')),
  incident_id    TEXT,
  processed      INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_events_unprocessed ON events(processed, ts);
CREATE INDEX IF NOT EXISTS idx_events_incident ON events(incident_id);

CREATE TABLE IF NOT EXISTS incidents (
  incident_id  TEXT PRIMARY KEY,
  created_ts   TEXT NOT NULL,
  updated_ts   TEXT NOT NULL,
  signal_kind  TEXT NOT NULL CHECK (signal_kind IN ('bait','behavior')),
  confidence   TEXT NOT NULL CHECK (confidence IN ('high','medium','low')),
  score        INTEGER NOT NULL,
  severity     TEXT NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  status       TEXT NOT NULL CHECK (status IN ('open','needs_review','closed')),
  source_ips   TEXT NOT NULL DEFAULT '[]',
  token_ids    TEXT NOT NULL DEFAULT '[]',
  stages       TEXT NOT NULL DEFAULT '[]',
  rules_hit    TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS signals (
  signal_id      INTEGER PRIMARY KEY AUTOINCREMENT,
  ts             TEXT NOT NULL,
  event_id       TEXT NOT NULL REFERENCES events(event_id),
  token_id       TEXT,
  rule           TEXT NOT NULL,
  points         INTEGER NOT NULL,
  incident_id    TEXT REFERENCES incidents(incident_id)
);

CREATE TABLE IF NOT EXISTS analyses (
  incident_id           TEXT PRIMARY KEY REFERENCES incidents(incident_id),
  ts                    TEXT NOT NULL,
  source                TEXT NOT NULL CHECK (source IN ('llm','rules')),
  valid                 INTEGER NOT NULL,
  based_on_event_count  INTEGER NOT NULL,
  body                  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS actions (
  action_id    INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_id  TEXT NOT NULL REFERENCES incidents(incident_id),
  ts           TEXT NOT NULL,
  kind         TEXT NOT NULL CHECK (kind IN ('disable_bait','revoke_credential','block_publish','notify')),
  target       TEXT,
  tier         TEXT NOT NULL CHECK (tier IN ('auto','approval')),
  status       TEXT NOT NULL CHECK (status IN ('done','pending','approved','rejected')),
  decided_by   TEXT,
  decided_ts   TEXT,
  scope_ip     TEXT,
  mode         TEXT CHECK (mode IN ('block','divert'))
);

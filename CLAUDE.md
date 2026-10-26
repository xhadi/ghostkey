# Ghostkey — project guide for Claude Code

Team ByteSentinels, CyberThon 2026 (KFU), digital supply chain track. Demo day: Sunday 25 Oct 2026.
This file is the single source of truth. If code and this file disagree, this file wins until the team changes it.

## What we are building (one line)

Ghostkey turns the use of bait keys inside software-development services we own (Git + package registry)
into ONE incident story ordered by supply-chain stage (source → build → publish), with evidence and a goal
hypothesis, so a small security team can investigate and respond faster.

The bait itself is NOT our innovation (Thinkst, GitGuardian, Tracebit already do it).
Our value is: correlation into one incident, stage ordering, evidence-linked analysis, proportional response.

## Hard rules (never break these)

1. No real secrets anywhere. Every token in this repo is synthetic. Never commit a `.env` with real values.
2. All attack activity runs only inside our own Docker environment. Never point scripts at GitHub.com, npmjs.com or any system we don't own.
3. The decoy network has NO internet access (`internal: true`). Do not add egress to it.
4. We never claim to redirect sessions from external services. Routing happens only at OUR gateway, in front of OUR services.
5. The LLM never decides actions on its own. It returns a hypothesis with evidence. Auto actions are limited to the list in "Response tiers".
6. Never invent results. Test numbers come only from `tests/` runs.
7. Stay inside your own folder (see Ownership). Changing anything in `contracts/` or `common/` needs Hadi's OK first.

## Ownership

| Folder | Owner | Writes to DB |
|---|---|---|
| `gateway/` | Hadi | inserts `events`; reads `actions` (to apply approved containment) |
| `core/` (correlation + scoring + actions) | Hadi | updates `events.incident_id/processed`, writes `incidents`, `signals`, inserts `actions` |
| `brain/` (behavior rules + LLM analyst) | Ghalia | writes `analyses` only; `brain/rules.py` is a pure function called by `core/` |
| `env/`, `attacker/`, `tests/sessions/` | Renad | nothing (creates services, seed data, baits, attack scripts) |
| `dashboard/` | Abbas | updates `actions.status/decided_by/decided_ts/mode` only; everything else read-only |
| `contracts/`, `common/` | Hadi (shared) | — |

## Architecture

```
attacker / ci-runner (devnet 172.30.0.0/24)
        │  HTTP
        ▼
gateway (mitmproxy reverse proxy)  :8080 → Gitea   :8081 → Verdaccio
   │ token in baits.json?  yes → decoy service (decoynet, internal)  + swap to decoy credential
   │                       no  → real service  (realnet, internal)   unchanged
   ▼ insert event
SQLite data/ghostkey.db  (WAL)
   ▲               ▲                 ▲
core.worker     brain.worker      dashboard (Streamlit :8501)
correlate+score  analyst JSON     incident story + approvals
```

Processes (each is its own docker compose service, all share the `gkdata` volume at `/app/data`):
- `gateway`: `mitmdump -s gateway/addon.py` with two reverse modes.
- `core`: `python -m core.worker` — loop every 1s over `events WHERE processed=0`.
- `brain`: `python -m brain.worker` — loop every 2s over incidents whose event count changed since last analysis.
- `dashboard`: `streamlit run dashboard/app.py` — auto-refresh every 2s.

Always open the DB through `common/db.py` (`connect()` sets WAL + busy_timeout). Do not open SQLite any other way.
Do NOT access the DB from the host through a bind mount on Docker Desktop (WAL over the VM boundary is unreliable). Use the containers.

## Data contracts

Full SQL: `contracts/schema.sql`. Examples: `contracts/*.example.json`. Fixtures: `fixtures/*.jsonl`.

### events (written by gateway)
`event_id` (evt_ + 8 hex), `ts` (ISO 8601 UTC, Z), `session_id`, `source_ip`, `user_agent`,
`token_kind` (bait | real | unknown | none), `bait_id`, `credential_id`, `stage` (source | build | publish | unknown),
`service` (git | npm), `method`, `path`, `action`, `target`, `status_code`, `result` (ok | denied | error),
`routed_to` (decoy | real | blocked), `incident_id` (NULL until core sets it), `processed` (0/1).

- `session_id` = `"s_" + sha1(source_ip + "|" + (bait_id or credential_id or "anon"))[:8]`.
- `stage`: bait events take the bait's stage from `baits.json`. Every other event (`token_kind` real, unknown, none) derives it from `action`:
  `list_repos`, `clone`, `api_read`, `api_write` → source; `login`, `install`, `search` → build; `push`, `publish` → publish; `other` → unknown.
- An incident's `stages` = distinct stages of its events, ordered source → build → publish, `unknown` left out.

### action classification (gateway)
git (Gitea): `GET /api/v1/user/repos`, `/api/v1/repos/search` → `list_repos`; `info/refs?service=git-upload-pack` or `POST .../git-upload-pack` → `clone`;
`git-receive-pack` → `push`; other `GET /api/v1/*` → `api_read`; other non-GET `/api/v1/*` → `api_write`; anything else → `other`.
npm (Verdaccio): `GET /-/whoami` → `login`; `GET /-/v1/search` → `search`; `PUT /<pkg>` → `publish`; `GET /<pkg>` or tarball → `install`; else `other`.
`target` = `owner/repo` for git, package name (decoded, e.g. `@kfu/build-utils`) for npm.

### token extraction (gateway)
Check `Authorization` in this order: `token X`, `Bearer X`, `Basic base64(user:X)` (git over HTTP sends the token as the password).
Bait match = exact string match against `contracts/baits.json` (no visible prefix on purpose).
Real match = `sha256(token)` found in `contracts/credentials.json`.

### routing (gateway)
- bait → change upstream to the decoy service AND replace the credential with the decoy service account token
  (`DECOY_GIT_TOKEN` / `DECOY_NPM_TOKEN` from env). The bait string itself is valid nowhere except our gateway.
- real or unknown → forward unchanged to the real service.
- Run mitmproxy with `--set keep_host_header=true`. Gitea `ROOT_URL` and Verdaccio `VERDACCIO_PUBLIC_URL` on BOTH real and decoy point to the gateway, so clone URLs and tarball URLs never leak internal hosts.
- Decoy credential header (verified 24 Oct on gitea 1.22 + verdaccio 5.33):
  - Gitea: send `Authorization: token <DECOY_GIT_TOKEN>`. Works on API, clone and push. (`Bearer` and `Basic <any user>:<token>` also work.)
  - Verdaccio: send `Authorization: Bearer <DECOY_NPM_TOKEN>` ONLY. `token X` and `Basic user:<token>` are silently treated as anonymous.
- npm `GET /-/whoami` returns 200 even without valid auth (body `{}`). For `login`, set `result` from the body: `{}` → denied, has `username` → ok.

### env notes (verified 24 Oct)
- Verdaccio's default config has an `npmjs` uplink and `proxy: npmjs` on every package. Remove `uplinks` and every `proxy:` line on BOTH real and decoy, or they call registry.npmjs.org (on `internal` networks they hang retrying).
- Verdaccio token: `PUT /-/user/org.couchdb.user:<name>` with `{"name","password"}` returns it. It lives in `/verdaccio/storage`, so keep the named storage volume or recreate the token on startup.
- Gitea token: `gitea admin user generate-access-token --username <u> --token-name <n> --scopes all` (run with `docker exec -u git`).
- Gitea 1.22 does not enforce token scopes on git smart-HTTP (a read-only token can push). Don't rely on scopes to limit a token.

### incidents (written by core)
`incident_id` (INC-001…), `created_ts`, `updated_ts`, `signal_kind` (bait | behavior), `confidence` (high | medium | low),
`score`, `severity`, `status` (open | needs_review | closed), and JSON-text arrays `source_ips`, `token_ids`, `stages`, `rules_hit` (`[{rule, points, event_id}]`).

### signals (written by core)
Every counted rule hit, including behavior hits that did not reach the incident threshold. `incident_id` may be NULL.
`token_id` = the event's `bait_id` or `credential_id`.
A repeated hit of a rule that is already counted is NOT stored, so an incident's `signals` rows always match its `rules_hit`.

### analyses (written by brain)
`incident_id`, `ts`, `source` (llm | rules), `valid` (0/1), `based_on_event_count`, `body` (JSON, see below).

### actions (inserted by core, decided by dashboard)
`incident_id`, `kind` (disable_bait | revoke_credential | block_publish | notify), `target`, `tier` (auto | approval),
`status` (done | pending | approved | rejected), `decided_by`, `decided_ts`,
`scope_ip` (core sets it on `revoke_credential`: the source IP the decision applies to; NULL for other kinds),
`mode` (block | divert; the dashboard sets it when the reviewer approves a `revoke_credential`; NULL while pending, when rejected and for other kinds).
`common/db.py init()` adds `scope_ip` and `mode` to an older DB with `ALTER TABLE`. `python -m common.reset_db` empties all tables.

## Correlation (core)

An event joins an existing open incident if ANY of:
1. same `bait_id` or `credential_id` as the incident (a real-token event with zero raw behavior hits does NOT join through the same credential), or
2. same `source_ip` as the incident and within 30 minutes of the incident's last event.
Otherwise a bait event opens a new incident; a real-token event only opens one when behavior points reach the threshold.
Events from real tokens with zero rule hits keep `incident_id = NULL`, unless they join an open incident through rule 2 (same IP within 30 minutes).
Reason: normal CI traffic with the same credential must not be pulled into a behavior incident.
When a behavior incident opens, attach the earlier events (and their `signals`) that counted toward the threshold.

## Scoring (initial weights, tune after tests)

Each rule counts at most once per incident (first hit wins).
Before a behavior incident exists, each rule counts at most once per `credential_id` within the 30-minute window (first hit wins).

| rule | points | applies to | owner |
|---|---|---|---|
| `bait_use` | 60 | any bait event | core |
| `second_stage_bait` | 20 | bait from a stage the incident has not seen yet | core |
| `bait_write_or_publish` | 15 | bait event with action push/publish/api_write | core |
| `new_source` | 20 | real token from an IP not in its baseline | brain/rules.py |
| `out_of_scope` | 25 | real token, action or target not in its baseline | brain/rules.py |
| `unexpected_publish` | 35 | real token, publish/push when baseline says `may_publish: false` | brain/rules.py |

- Behavior: sum hits for the same `credential_id` within 30 minutes; open an incident at ≥ 60 (so one hit alone never opens one).
- Severity: < 40 low, 40–69 medium, 70–89 high, ≥ 90 critical.
- Confidence is separate from severity: bait → high; behavior → medium at most.
- Status: bait → open; behavior → needs_review.

`brain/rules.py` interface (pure, no DB access):
```python
def behavior_hits(event: dict, baseline: dict | None) -> list[dict]:
    """Return [{"rule": "new_source", "points": 20}, ...] for one real-token event."""
```
Baselines live in `contracts/baselines.json`, keyed by `credential_id`.

Reference behavior (raw hits per event, before core's once-per-rule counting):
- Rules are checked and returned in this fixed order: `new_source`, `out_of_scope`, `unexpected_publish`.
- `baseline is None` → `[]`.
- `out_of_scope` fires if the action is not in `allowed_actions` OR the target is not None and not in `allowed_targets`.

| event | raw output |
|---|---|
| `evt_n0000001` | `[]` |
| `evt_n0000002` | `[]` |
| `evt_s2000001` | `[new_source 20]` |
| `evt_s2000002` | `[new_source 20, out_of_scope 25]` |
| `evt_s2000003` | `[new_source 20, out_of_scope 25, unexpected_publish 35]` |

After core's once-per-rule counting: 20 + 25 + 35 = 80 (Scenario 2).

## Analyst output (brain)

Must match `contracts/analysis.example.json`:
`summary`, `observed` (list of action labels), `hypothesis {label, confidence}`, `evidence_event_ids`,
`alternatives` (at least one, each `{label, why}`), `assets_at_risk`, `recommended_action`, `limits`.
- Allowed hypothesis labels: `recon_only`, `source_theft`, `package_publish`, `credential_harvest`, `automated_secret_scanner`, `unknown`.
- `brain/validate.py` rejects output if any `evidence_event_ids` entry is not an event of that incident, if `alternatives` is empty, or if a label is not allowed. Rejected → store the rules-only analysis with `source = "rules"`.
- No API key or LLM error → rules-only analysis. The system must work fully without the LLM.
- Arabic text for the demo goes in `summary`, `why`, `recommended_action`, `limits`. Labels stay in English.
- Send only incident events to the LLM (all synthetic). Never send env vars or tokens.

## Response tiers

- auto (core inserts with `status=done`): notify, keep evidence, `disable_bait` for an exposed bait.
- `notify`: core inserts exactly ONE (target `security-team`, tier `auto`, status `done`) when it opens any incident (bait or behavior).
- approval (core inserts with `status=pending`, dashboard approves/rejects): `revoke_credential`, `block_publish`.
- `revoke_credential` (pending): core inserts one per (incident, credential, source IP) for real-token events that have behavior hits. The reviewer chooses Block or Divert to decoy, or rejects. Block/Divert are enforced only at OUR gateway, only for that credential from that IP. Nothing is changed on Gitea or Verdaccio, and nothing is contained automatically.
- forbidden: any action on external systems, deleting data, changing permissions because the LLM said so.

## Demo scenarios (expected results — these are the acceptance tests)

Scenario 1 — leaked bait (attacker container 172.30.0.66):
`BAIT-SRC-01` on Gitea: list repos → clone `ops/ci-pipeline` (decoy) → finds `BAIT-CI-02` in its `.npmrc` →
on Verdaccio: whoami → publish `@kfu/build-utils@9.9.9`.
Expected: exactly 1 incident, `signal_kind=bait`, `confidence=high`, score 95 (60+20+15), `critical`, stages `["source","build"]`,
every event `routed_to=decoy`, zero events to real, one `notify` action done, one `disable_bait` action done per bait, analyst alternative includes `automated_secret_scanner`.

Scenario 2 — stolen real credential, no bait (attacker container 172.30.0.77):
`REAL-CI-01` (npm token of `ci-bot`, baseline: source 172.30.0.10, action install, target `@kfu/build-utils`, no publish):
install `@kfu/build-utils` from new IP → install `@kfu/payments-sdk` → publish `@kfu/build-utils@9.9.10`.
Expected: 1 incident, `signal_kind=behavior`, `confidence=medium`, score 80 (20+25+35), `high`, `needs_review`,
every event `routed_to=real`, one `notify` action done, one `revoke_credential` action `pending`.

Scenario 3 — leaked publish script (attacker3 172.30.0.88):
`BAIT-PUB-03` (from `ops/release-tools/scripts/publish.sh`) on Verdaccio: whoami → search `@kfu` → install `@kfu/payments-sdk` → publish `@kfu/payments-sdk@6.6.6`.
Expected: exactly 1 incident, `signal_kind=bait`, `confidence=high`, score 75 (60+15), `high`, stages `["publish"]`,
every event `routed_to=decoy`, zero events to real, one `notify` action done, one `disable_bait` action done for `BAIT-PUB-03`, hypothesis `package_publish`.

Scenario 4 — scanner with a leaked doc token (attacker4 172.30.0.99, user agent `ghostkey-demo-scanner/1.0`):
`BAIT-DOC-04` (from `dev/docs` `runbooks/deploy.md`) on Gitea, read-only: `GET /api/v1/user` → `user/repos` → `repos/search` → `repos/ops/ci-pipeline/contents/README.md`.
Expected: exactly 1 incident, `signal_kind=bait`, `confidence=high`, score 60, `medium`, stages `["source"]`,
every event `routed_to=decoy`, one `notify` action done, one `disable_bait` action done for `BAIT-DOC-04`, rules-only hypothesis `recon_only`, analyst alternative includes `automated_secret_scanner` (a live LLM may instead pick `automated_secret_scanner` as the hypothesis itself).

Noise — dev-laptop 172.30.0.50: anonymous Gitea search, anonymous npm install (refused), one Gitea request with a mistyped token (`token_kind=unknown`):
zero signals, zero incidents.

Normal traffic — ci-runner 172.30.0.10 with `REAL-CI-01` installing `@kfu/build-utils`: zero signals, zero incidents.

You can test core, brain and dashboard WITHOUT the gateway:
`docker compose run --rm core python -m fixtures.load_fixtures --reset` loads `fixtures/*.jsonl` into the DB with timestamps shifted to now.
Add `--fake-core` to ALSO write the expected incidents, signals, analyses and actions from `fixtures/expected_state.json`.
That is for building the dashboard before core/brain exist. DEVELOPMENT ONLY — never in the demo, and never when testing core or brain.

## Commands

```bash
docker compose pull                       # do this on good wifi (Saturday night)
docker compose up -d --build
docker compose exec attacker bash /work/scenario1.sh
docker compose exec attacker2 bash /work/scenario2.sh
docker compose exec attacker3 bash /work/scenario3.sh
docker compose exec attacker4 bash /work/scenario4.sh
docker compose exec dev-laptop bash /work/noise.sh
bash attacker/run_all.sh                  # normal, noise, scenario1..4 in order (each starts with a 3 s countdown, DEMO_START_DELAY)
docker compose run --rm core python -m fixtures.load_fixtures --reset
docker compose logs -f gateway core brain
# dashboard: http://localhost:8501
```

## Git workflow

- Repo is private. Branch per person: `hadi/gateway`, `ghalia/brain`, `renad/env`, `abbas/dashboard`.
- Small commits, pull `main` often. Hadi merges to `main`.
- Never commit `data/`, `.env`, or `node_modules/`.

## Coding style

- Python 3.12, standard library first. Allowed extra deps: `mitmproxy`, `streamlit`, `pandas`, and one LLM SDK.
- Small functions, type hints, no clever tricks. Teammates are learning; prefer readable over short.
- Every module that writes to the DB has a `tests/test_<module>.py` using the fixtures.
- Times are always UTC ISO strings ending in `Z`.
- When unsure about a contract detail, stop and ask the human instead of guessing.

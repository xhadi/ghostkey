# Containment Choices and Decision Evidence Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The reviewer's Block / Divert / Reject decision takes real effect at our gateway for one credential from one IP, and the incident page shows the evidence needed to decide.

**Architecture:** Two new nullable columns on `actions` (`scope_ip` set by core, `mode` set by the dashboard). The gateway reads approved containments per request and answers 403 or reroutes to the decoy. The dashboard gets three-way decisions plus three evidence panels built from data already in the DB and `contracts/*.json`.

**Tech Stack:** Python 3.12 stdlib, SQLite via `common/db.py`, mitmproxy addon, Streamlit, `unittest`.

**Spec:** `docs/superpowers/specs/2026-10-25-containment-and-evidence-design.md` (read it first; section letters below refer to it).

## Global Constraints

- No change to scoring rules, weights, thresholds; scenario 1/2 expected results in CLAUDE.md stay exact (95 critical, 80 high, etc.).
- Containment only at our gateway; nothing touches Gitea/Verdaccio admin APIs; no automatic containment.
- Every DB access through `common/db.py` (`connect()`), never another way; never open the DB from the host via the bind mount.
- Times are UTC ISO strings ending in `Z`.
- Dashboard HTML builders: every DB/contract string through `views.esc()`, each builder returns one line of HTML (no `\n\n`).
- Keep each file's existing line endings (many are CRLF). Match surrounding style: small functions, type hints, docstrings, readable over clever.
- Do not edit CLAUDE.md's demo date. Do update its contract text (Task 1).
- Never commit `data/`, `.env`, `node_modules/`, `attacker/.secrets/`.
- Commit messages end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.
- Host test command: `python -m unittest discover -s tests -t .` (gateway addon tests skip on host; run them in the gateway container, see Task 3).

## Review Focus

1. Normal CI traffic (REAL-CI-01 from 172.30.0.10) after a decision on 172.30.0.77 must still go to real and must not join INC-002 → Task 2 and Task 3 tests.
2. A decision clicked twice, or Block on an already-decided action, must change nothing → Task 4 guard test.
3. A `ghostkey.db` created before this change (no new columns) must keep working after restart → Task 1 migration test.
4. Divert when the decoy env vars are missing must not leak to real → Task 3 test (falls back to 503 blocked).
5. Attacker-controlled `target`/`source_ip`/`path` values inside the new panels must be escaped → Task 5 escaping test.

---

### Task 1: Schema columns, migration, reset command, contract text

**Files:**
- Modify: `contracts/schema.sql` (actions table)
- Modify: `common/db.py` (`init`)
- Create: `common/reset_db.py`
- Modify: `fixtures/expected_state.json` (revoke action gets `"scope_ip": "172.30.0.77"`), `fixtures/load_fixtures.py` (`write_fake_core` inserts `scope_ip`; use named columns, not positional VALUES, for actions)
- Modify: `CLAUDE.md` — actions contract (`scope_ip`, `mode`), ownership table (dashboard also writes `actions.mode`; gateway reads `actions`), Correlation section (spec B.3 rule), Response tiers (Block/Divert at our gateway). Not the date.
- Test: `tests/test_common_db.py` (create)

**Interfaces:**
- Produces: `actions.scope_ip TEXT NULL`, `actions.mode TEXT NULL CHECK (mode IN ('block','divert'))`; `db.init(conn)` guarantees both columns exist; `python -m common.reset_db` empties all tables via `db.reset`.

- [ ] **Step 1: Write failing tests** in `tests/test_common_db.py`:
  - `test_init_adds_new_action_columns_to_old_db`: create a temp DB, create the OLD `actions` table (copy current DDL without the two columns) plus `incidents`, call `db.init(conn)`, assert `{"scope_ip","mode"} <= {r["name"] for r in conn.execute("PRAGMA table_info(actions)")}`.
  - `test_init_twice_is_harmless`: `db.init` twice on a fresh DB raises nothing; columns present once.
  - `test_mode_check_rejects_unknown_value`: inserting an action with `mode='nuke'` raises `sqlite3.IntegrityError`.
- [ ] **Step 2: Run** `python -m unittest tests.test_common_db -v` → FAIL (columns missing).
- [ ] **Step 3: Implement.** Add the two columns to the DDL. In `common/db.py` add `_add_missing_action_columns(conn) -> None` called from `init()` after the script: for each missing column run `ALTER TABLE actions ADD COLUMN ...`; swallow `sqlite3.OperationalError` whose message contains `duplicate column` (another process won the race). Create `common/reset_db.py` with a `main()` that connects, inits, resets, prints `"ghostkey.db emptied"`. Update fixtures and `write_fake_core`. Update CLAUDE.md text.
- [ ] **Step 4: Run** `python -m unittest discover -s tests -t .` → all pass (existing dashboard/core tests still green with the fixture change).
- [ ] **Step 5: Commit** `Add actions.scope_ip/mode with startup migration and reset_db command`.

---

### Task 2: Core — scoped revoke prompts and correlation fix

**Files:**
- Modify: `core/engine.py` (`insert_action`, `open_behavior_incident`, `join_incident`, `find_incident`, `process_event`)
- Test: `tests/test_core.py`

**Interfaces:**
- Consumes: `actions.scope_ip` (Task 1).
- Produces: every `revoke_credential` row core inserts has `target=credential_id`, `scope_ip=<source IP>`; at most one per (incident_id, target, scope_ip).
- `insert_action(conn, incident_id, ts, kind, target, tier, status, scope_ip: str | None = None) -> None`
- `ensure_revoke_prompt(conn: sqlite3.Connection, incident_id: str, event: dict) -> None` — inserts a pending approval `revoke_credential` for (event credential_id, event source_ip) unless one exists for that incident.
- `find_incident(conn, event, allow_token_match: bool = True) -> dict | None`

- [ ] **Step 1: Write failing tests** (new tests use `brain.rules.behavior_hits` with `db.load_json("baselines.json")`, same as `fake_behavior_hits`):
  - `test_revoke_prompt_is_scoped_to_attacker_ip`: load scenario2, run core → INC-002 has exactly one `revoke_credential`, `scope_ip == "172.30.0.77"`, `target == "REAL-CI-01"`, actions order still notify then revoke.
  - `test_zero_hit_real_event_does_not_join_by_credential`: scenario2 processed; then insert a copy of `evt_n0000001` with a new event_id, `ts` 1 minute after the last scenario2 event, run core → its `incident_id` is NULL; INC-002 event count and score (80) unchanged.
  - `test_new_ip_with_hits_joins_and_asks_again`: scenario2 processed; insert a real-token install of `@kfu/build-utils` from `172.30.0.99` (REAL-CI-01) → joins INC-002; INC-002 now has two pending revokes, scope_ips `{"172.30.0.77","172.30.0.99"}`; score still 80.
  - `test_repeat_from_same_ip_adds_no_second_prompt`: another `.77` event with hits → still one revoke for `.77`.
- [ ] **Step 2: Run** `python -m unittest tests.test_core -v` → new tests FAIL.
- [ ] **Step 3: Implement.** In `process_event`, for `token_kind == "real"` compute hits before `find_incident` (they do not depend on the incident) and pass `allow_token_match=bool(hits)`; bait/other unchanged. In `open_behavior_incident`, after `notify`, call `ensure_revoke_prompt` once per distinct source IP of the attached events (threshold event's IP first). In `join_incident`, call it when the event is `real` and `hits` is non-empty.
- [ ] **Step 4: Run** `python -m unittest tests.test_core tests.test_worker -v` then the full suite → all pass, existing scenario assertions untouched.
- [ ] **Step 5: Commit** `Core: scope revoke prompts to source IP; zero-hit real events no longer join by credential`.

---

### Task 3: Gateway — enforce Block / Divert

**Files:**
- Modify: `gateway/logic.py`, `gateway/addon.py`
- Test: `tests/test_gateway_logic.py`, `tests/test_gateway_addon.py`

**Interfaces:**
- Consumes: approved `revoke_credential` rows with `mode` and `scope_ip` (Tasks 1, 4).
- `logic.containment_route(mode: str | None, service: str, env: dict) -> dict | None` — `None` → `None`; `"block"` → `{"routed_to": "blocked", "status": 403, "body": b"forbidden"}`; `"divert"` → the same dict `route_for("bait", service, env)` returns (refactor the decoy part into a shared helper); if that is `blocked`, return it with `"status": 503, "body": b"blocked"`.
- `Gateway.containment_mode(self, credential_id: str, source_ip: str) -> str | None` — `SELECT mode FROM actions WHERE kind='revoke_credential' AND status='approved' AND target=? AND scope_ip=? ORDER BY decided_ts DESC, action_id DESC LIMIT 1`.

- [ ] **Step 1: Write failing tests.**
  - logic: `test_containment_none`, `test_containment_block_is_403`, `test_containment_divert_npm_uses_bearer_decoy` (upstream `http://verdaccio-decoy:4873`, authorization `Bearer <DECOY_NPM>`), `test_containment_divert_without_decoy_env_is_503_blocked`.
  - addon (helper inserts an incident row first — `actions.incident_id` is a foreign key — then an action with given status/mode/scope_ip): 
    - `test_block_answers_403_and_records_blocked_event`: approved block for (REAL-CI-01, 172.30.0.77); npm GET from `.77` with `Bearer REAL_TOKEN` → `flow.response.status_code == 403`; one event row `routed_to="blocked"`, `status_code=403`, `result="denied"`, `token_kind="real"`, `credential_id="REAL-CI-01"`.
    - `test_divert_goes_to_decoy_with_decoy_credential`: approved divert → `flow.request.host == "verdaccio-decoy"`, Authorization `Bearer DECOY_NPM`, after `answer()` the row has `routed_to="decoy"`, `token_kind="real"`.
    - `test_same_credential_other_ip_is_untouched`: approved block for `.77`; request from `172.30.0.10` → no response set, host stays real, row `routed_to="real"`.
    - `test_pending_or_rejected_decision_has_no_effect`.
    - `test_secret_never_in_db` still passes for the new paths (no token strings in any row).
- [ ] **Step 2: Run** logic tests on host (`python -m unittest tests.test_gateway_logic -v`) → FAIL; addon tests in the container: `docker compose run --rm --no-deps gateway python -m unittest tests.test_gateway_addon -v` (if the image lacks `tests/`, use `docker compose run --rm --no-deps -v "$PWD:/app" gateway ...` or the equivalent that the compose file supports; report which command worked).
- [ ] **Step 3: Implement.** In `_route_request`, when `token["token_kind"] == "real"`, look up the mode and let `containment_route` override `route`. Blocked responses use the route's `status`/`body` (default 503/`b"blocked"`) and are recorded in the request hook as today. Divert uses `point_at_decoy`. A lookup exception falls into the existing `request()` handler (503, never forward).
- [ ] **Step 4: Run** both test files (host + container) → pass; full host suite → pass.
- [ ] **Step 5: Commit** `Gateway: enforce approved Block/Divert for one credential from one IP`.

---

### Task 4: Dashboard — three-way decision and honest decided lines

**Files:**
- Modify: `dashboard/queries.py`, `dashboard/views.py`, `dashboard/app.py`, `dashboard/theme.py` (only if three buttons need layout tweaks)
- Test: `tests/test_dashboard.py`

**Interfaces:**
- Consumes: `actions.scope_ip`, `actions.mode`; event `routed_to` values from Task 3.
- `queries.decide_action(conn, action_id: int, decision: str, decided_by: str) -> bool` — `decision` in `{"block","divert","reject","approve"}`; `block`/`divert` only match `kind='revoke_credential' AND scope_ip IS NOT NULL`, set `status='approved'`, `mode=decision`; `approve` only matches `kind != 'revoke_credential'`; `reject` matches any; all keep `tier='approval' AND status='pending'`. Unknown decision → `ValueError`.
- `queries.containment_effect(conn, action: dict) -> int` — events with `credential_id=target`, `source_ip=scope_ip`, `routed_to` = `blocked` (mode block) or `decoy` (mode divert), `ts >= decided_ts`; 0 if not an approved revoke.
- `views.decided_action_html(action: dict, effect: int = 0) -> str`, `views.auto_log_html(actions: list[dict], effects: dict[int, int] | None = None) -> str`.

Exact copy:
- Pending revoke sentence: `Stop {target} from {scope_ip} at our gateway`
- Buttons: `Block`, `Divert to decoy`, `Reject` (non-revoke kinds keep `Approve`, `Reject`)
- Decided: `Blocked at our gateway: {target} from {scope_ip} · {n} requests stopped since {HH:MM:SS} UTC` / `Diverted to decoy: {target} from {scope_ip} · {n} requests diverted since {HH:MM:SS} UTC` / `Rejected by {decided_by} at {HH:MM:SS} UTC, nothing changed`
- Note under buttons: `Applies only to this credential from this IP. Rotating the credential is still up to its owner. Ghostkey never changes external systems.`
- NULL scope_ip: buttons disabled, note `No IP scope on this action; cannot be enforced`.
- Remove the `Revoked credential` wording everywhere.

- [ ] **Step 1: Write failing tests:** block sets approved+mode and returns True; second call returns False and changes nothing; divert on a NULL-scope revoke returns False; approve on revoke returns False; reject works; `ValueError` on `"nuke"`; `containment_effect` counts only matching credential+IP+routed_to after `decided_ts` (insert one before, one after, one other IP); decided lines contain the exact copy above and escape a `<script>` target; `"Revoked credential"` appears nowhere in `auto_log_html` output. Update existing tests that pass `"approve"` for the revoke action.
- [ ] **Step 2: Run** `python -m unittest tests.test_dashboard -v` → new tests FAIL.
- [ ] **Step 3: Implement** queries, views, and `app.render_response` (three buttons inside the existing `decide_{action_id}` container; compute `effects` for approved revokes and pass to `auto_log_html`).
- [ ] **Step 4: Run** dashboard tests + full suite → pass; `python -c "import ast;ast.parse(open('dashboard/app.py',encoding='utf-8').read())"` OK.
- [ ] **Step 5: Commit** `Dashboard: Block / Divert / Reject decisions with real effect counts`.

---

### Task 5: Dashboard — evidence panels

**Files:**
- Modify: `dashboard/views.py`, `dashboard/app.py` (`render_detail`), `dashboard/theme.py`
- Test: `tests/test_dashboard.py`

**Interfaces:**
- Consumes: `queries.list_events`, `queries.list_sessions` (exists), `db.load_json("baselines.json")`, `db.load_json("credentials.json")`.
- `views.reached_real_html(events: list[dict]) -> str`
- `views.baseline_html(incident: dict, events: list[dict], baselines: dict, credentials: list[dict]) -> str` — `""` when no real credential with a baseline is in the incident.
- `views.elsewhere_html(incident: dict, sessions: list[dict]) -> str` — `""` when nothing applies.

Rules (spec D, panels 1–3): writes = `publish, push, api_write`; reads = `install, clone, api_read, list_repos, search, login`; only `routed_to='real' AND result='ok'`; group by (service, target) with count and first time. Empty → `Nothing reached the real services — every request went to the decoy`. With a write add `Check this package version or push in the real service. A human does this; Ghostkey does not delete anything.` Baseline rows: `Source IPs`, `Actions`, `Targets`, `Publishing` (`allowed`/`not allowed` vs `yes`/`no`); observed values outside the baseline get class `gk-out`; header shows `owner` and `service` only (never `sha256`). Elsewhere: sessions with `token_kind == "real"`, token in `incident["token_ids"]`, `incident_id != incident["incident_id"]`; line `Containment applies only to the attacker's IP, so these keep working.` with IP, requests, last seen, and the triage verdict pill (`views.session_verdict`).
Page order in `render_detail`: header → reached_real → stage map → baseline → elsewhere → score ledger → analyst → response → event log. Load the two JSON files once per run of `live()`.

- [ ] **Step 1: Write failing tests** (fixture DB): INC-002 reached_real contains `Written` and `@kfu/build-utils`; INC-001 contains `Nothing reached the real services`; INC-002 baseline marks `172.30.0.77`, `@kfu/payments-sdk`, `publish` with `gk-out` and does not mark `install`, contains `ci-bot`, not `sha256`; INC-001 baseline is `""`; INC-002 elsewhere lists `172.30.0.10`; INC-001 elsewhere is `""`; a hostile `target`/`source_ip` is escaped in all three; no `\n\n`.
- [ ] **Step 2: Run** → FAIL.
- [ ] **Step 3: Implement** builders, CSS (reuse existing tokens: alarm, amber, real, rule), and `render_detail` order.
- [ ] **Step 4: Run** dashboard tests + full suite → pass.
- [ ] **Step 5: Commit** `Dashboard: what reached real, baseline vs observed, same credential elsewhere`.

---

### Task 6: Brain — say when traffic was contained

**Files:**
- Modify: `brain/analyst_rules.py`, `brain/prompts/analyst.md`
- Test: `tests/test_brain_analyst_rules.py`

**Interfaces:**
- `analyst_rules.contained_count(events: list[dict]) -> int` — real-token events with `routed_to` in (`decoy`, `blocked`).
- `rules_analysis` summary gets one extra Arabic sentence when the count > 0, in the same register as the existing summary text, meaning: "after the reviewer's decision, N requests went to the decoy or were blocked at the gateway and did not reach the real service."

- [ ] **Step 1: Failing tests:** count is 0 for fixture scenario1 and scenario2; adding two scenario2-like events with `routed_to="decoy"` gives 2 and the summary contains the number; labels, `observed`, evidence ids, and `brain/validate.py` acceptance unchanged.
- [ ] **Step 2: Run** `python -m unittest tests.test_brain_analyst_rules -v` → FAIL.
- [ ] **Step 3: Implement**; add one line to `prompts/analyst.md` after the routed_to sentence: a real-token event with `routed_to` = `"decoy"` or `"blocked"` means a human reviewer contained that credential from that IP at our gateway, so it did not reach the real service.
- [ ] **Step 4: Run** brain tests + full suite → pass.
- [ ] **Step 5: Commit** `Brain: mention requests contained by the reviewer`.

---

### Task 7: Env — reset removes the diverted publish

**Files:**
- Modify: `env/seed.py` (`ATTACK_VERSIONS`), `env/reset_packages.sh` (top comment)

- [ ] **Step 1:** Add `(NPM_DECOY, DECOY_NPM_USER, "@kfu/build-utils", "9.9.10")` to `ATTACK_VERSIONS`; update the comment to list it.
- [ ] **Step 2:** `python -c "import ast;ast.parse(open('env/seed.py',encoding='utf-8').read())"` OK; `env/reset_packages.sh` still LF (`git ls-files --eol env/reset_packages.sh`).
- [ ] **Step 3: Commit** `Env: reset also removes the diverted 9.9.10 from the decoy`.

---

### Task 8: Live demo-flow verification (Docker)

No code unless a defect is found (then fix in the owning task's files with a test).

- [ ] **Step 1:** `docker compose up -d --build`; `bash env/reset_packages.sh`; `docker compose run --rm core python -m common.reset_db`.
- [ ] **Step 2:** Run spec F steps 1–3 (`normal.sh`, `scenario1.sh`, `scenario2.sh`); run `tests/sessions/check_scenarios.py` the way its docstring says → pass.
- [ ] **Step 3:** Approve Divert on INC-002 by calling `dashboard.queries.decide_action(conn, <id>, "divert", "rehearsal")` inside the dashboard container (same code path as the button).
- [ ] **Step 4:** `scenario2.sh` again → new `.77` events `routed_to='decoy'`, in INC-002, score still 80, `containment_effect` > 0. `normal.sh` again → `.10` events `routed_to='real'`, `incident_id` NULL.
- [ ] **Step 5:** Repeat Step 1 then Block instead of Divert → `.77` gets 403s, events `blocked`. Report every command and the observed numbers verbatim.

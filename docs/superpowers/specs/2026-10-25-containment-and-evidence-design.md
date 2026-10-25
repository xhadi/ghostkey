# Containment choices and decision evidence — design

Date: 2026-10-25 (demo is 2026-10-26). Owner: Hadi. Status: draft for approval.

## Why

At the demo we want judges to see three things:

1. Ghostkey tells normal users apart from abnormal or compromised ones.
2. The security person gets enough evidence to decide without trusting the score blindly.
3. The security person is in control, and their decision has a real effect.

Today point 3 is false. Approving `revoke_credential` only changes `actions.status`; the gateway keeps
forwarding the token to the real service, yet the dashboard then says "Revoked credential". A judge who
asks "run the attacker again" would see the attack still working. Point 2 is weak: the most important
fact of scenario 2 (the attacker's publish reached the REAL registry, HTTP 201) is buried in the event log.

## Goals

- When a behavior incident asks for approval, the reviewer chooses one of: **Block** (our gateway answers
  403), **Divert** (our gateway quietly sends the requests to the decoy, like bait traffic), or **Reject**
  (nothing happens, the decision is recorded).
- The decision applies to **one credential from one source IP** (the attacker's), not the whole credential,
  so the legitimate CI runner using the same token keeps working.
- The incident page shows: what reached the real services, the credential's baseline next to what was
  observed, and other places the same credential is used.
- The dashboard only states what really happened (counts of requests blocked or diverted since the decision).

## Non-goals

- No changes to scoring rules, weights or thresholds. Scenario 1 and 2 expected results stay exactly as in
  CLAUDE.md (scores 95 and 80, etc.).
- No learned baselines and no "publish without source" rule (slide "next steps" only).
- No action on external systems. Nothing is revoked inside Verdaccio or Gitea; containment happens only at
  our gateway (CLAUDE.md hard rule 4).
- No automatic containment. Block/Divert only happen after a human clicks (hard rule 5).
- No deleting the malicious package version; we only recommend that a human checks it.

## Anti-goals (would be a failure even if it "works")

- The dashboard claims an effect that did not happen.
- Normal CI traffic gets blocked, diverted, or pulled into the attacker's incident.
- Any scenario expected result in CLAUDE.md changes.

## Decided (by Hadi in conversation)

- Two containment modes, Block and Divert, chosen per decision by the reviewer, plus Reject.
- Scope = credential + attacker source IP.
- Priority if time runs out: (1) containment buttons + real effect, (2) "what reached real services" box,
  (3) baseline vs observed table, (4) "same credential elsewhere".

## Design

### A. Contract changes (`contracts/schema.sql`, `CLAUDE.md`) — Hadi owns, approved by this doc

`actions` gets two nullable columns:

- `scope_ip TEXT` — set by core when it inserts a `revoke_credential` action: the source IP the decision
  applies to. NULL for every other kind.
- `mode TEXT CHECK (mode IN ('block','divert'))` — set by the dashboard when the reviewer approves a
  `revoke_credential` action. NULL while pending, when rejected, and for every other kind.

Kind name stays `revoke_credential` (less churn in fixtures/tests); only the displayed wording changes.
Because `db.init()` uses `CREATE TABLE IF NOT EXISTS`, an existing `ghostkey.db` will not get the new
columns: `common/db.py` must add them with `ALTER TABLE ... ADD COLUMN` when missing (idempotent).

Ownership changes: dashboard may also write `actions.mode`; gateway may READ `actions` (still writes only
`events`).

### B. Core (`core/engine.py`)

1. `open_behavior_incident` inserts `revoke_credential` with `target = credential_id` and
   `scope_ip = event["source_ip"]` (the event that crossed the threshold).
2. One pending `revoke_credential` per (incident, credential, source IP), for every real-token event in the
   incident that has at least one raw behavior hit. At open time: one per distinct IP among the attached
   real-token events with hits (scenario 2 → exactly one, for 172.30.0.77, so existing "one pending revoke"
   assertions still hold). At join time (behavior OR bait incident): insert one if that triple has none yet.
   This is how the reviewer is asked again if the attacker moves to a new IP. If a legitimate IP gets a
   prompt (its event had hits), the reviewer rejects it — a human decides.
3. **Correlation fix.** Today a real-token event joins an open incident just because it has the same
   `credential_id`. That pulls normal CI traffic (same `REAL-CI-01`, IP 172.30.0.10) into INC-002 if
   `normal.sh` runs after scenario 2. New rule: a real-token event with **zero raw behavior hits** cannot
   join through the same-credential match; it can still join through the same-IP-within-30-minutes match.
   Bait events and real events with hits are unchanged. Update the "Correlation" section of CLAUDE.md.
   (For real-token events, behavior hits do not depend on the incident, so compute them before
   `find_incident`.)

### C. Gateway (`gateway/logic.py`, `gateway/addon.py`)

For every request whose token is `real`, look up an approved containment:
`SELECT mode FROM actions WHERE kind='revoke_credential' AND status='approved' AND target=? AND scope_ip=?
ORDER BY decided_ts DESC LIMIT 1` with (credential_id, source_ip). A per-request query is fine at demo
volume; keep it in a small function so it can be cached later. Put the decision logic in a pure function
in `logic.py` (for tests), the DB read in `addon.py`.

- `block` → gateway answers `403` itself, body `forbidden`, event `routed_to='blocked'`,
  `status_code=403`, `result='denied'`. Record the event in the request hook (as the existing blocked path
  does), because the response hook may not run for our own answer.
- `divert` → same as bait routing: upstream = decoy service for that port, Authorization replaced by the
  decoy credential (`DECOY_GIT_TOKEN` / `DECOY_NPM_TOKEN`, with the scheme rules in CLAUDE.md "routing").
  Event `routed_to='decoy'`. `token_kind` stays `real`, `credential_id` stays set, stage derived from action.
  If the decoy env var is missing, fall back to the existing `blocked` (503) behavior.
- No approved containment → unchanged (forward to real).
- If the lookup itself fails, answer 503 like the existing request-hook error path (never forward a request
  we could not check).

Diverted events keep flowing through core normally: they join INC-002 (same credential and they have hits,
or same IP), behavior rules may fire, but already-counted rules add nothing, so the score stays 80.

### D. Dashboard (`dashboard/`)

Response section, for a pending `revoke_credential`:
- Text: "Stop {target} from {scope_ip} at our gateway". Three buttons: **Block**, **Divert to decoy**,
  **Reject**. `queries.decide_action` accepts `block | divert | reject`; block/divert set
  `status='approved'` and `mode`; reject sets `status='rejected'`. Same WHERE-guard as today.
- Decided line, using only real counts: "Blocked at our gateway: REAL-CI-01 from 172.30.0.77 · N requests
  stopped since 15:44:10 UTC" (count events with that credential + IP and `routed_to='blocked'` after
  `decided_ts`), or "Diverted to decoy: … · N requests diverted since …" (`routed_to='decoy'`). Rejected:
  "Rejected by {decided_by} at …, nothing changed". Remove the "Revoked credential" wording.
- Short note under the buttons: "Applies only to this credential from this IP. Rotating the credential is
  still up to its owner."

New panels on the incident page, in this order under the header:

1. **What reached real services** (all incidents). From the incident's events with `routed_to='real'` and
   `result='ok'`: writes (`publish`, `push`, `api_write`) listed as "Written to the real {service}: {target}
   at {time}" in the alarm style, reads (`install`, `clone`, `api_read`, `list_repos`, `search`, `login`) as
   "Read from real: …" in the warning style, grouped by target with counts. If none: a calm line "Nothing
   reached the real services — every request went to the decoy" (this is scenario 1's story). If there was
   a write, add the recommendation "Check this package version / push in the real service. A human does
   this; Ghostkey does not delete anything."
2. **Baseline vs observed** (incidents with real-token events whose credential has a baseline). One row
   each for Source IPs, Actions, Targets, Publishing. Left: baseline values from `contracts/baselines.json`.
   Right: distinct observed values from the incident's events for that credential; values outside the
   baseline highlighted. Header shows owner and service from `contracts/credentials.json`
   (never show `sha256`). Read both files with `db.load_json`.
3. **Same credential elsewhere** (only when it applies). Sessions (reuse `queries.list_sessions`) whose
   token is in the incident's `token_ids` but which are not part of this incident: IP, requests, last seen,
   verdict pill. Line: "Containment applies only to the attacker's IP, so these keep working."

Existing panels (stage map, score ledger, analyst, event log) stay.

Decisions are final for the demo: no undo and no changing Block into Divert (the "pending only" guard
stays). A rehearsal starts from a clean state (see G), which removes every containment.

A `revoke_credential` row with NULL `scope_ip` (old DBs) shows its buttons disabled with the note
"No IP scope on this action; cannot be enforced". `fixtures/expected_state.json` gets
`scope_ip: "172.30.0.77"` on its revoke action so `--fake-core` data stays enforceable.

### D2. Brain (`brain/analyst_rules.py`, `brain/prompts/analyst.md`) — Ghalia's folder, change approved by Hadi (2026-10-25)

After a Divert, re-runs add `routed_to='decoy'` real-token events to INC-002 and brain re-analyses.
Without a change, the rules-only summary would say the attacker "published again" with no mention that it
went to the decoy, which contradicts the anti-goal. Change:
- `analyst_rules.py`: when an incident has real-token events with `routed_to` in (`decoy`, `blocked`), the
  summary/limits add one sentence (Arabic, like the rest of the demo text): N requests after the reviewer's
  decision went to the decoy / were blocked at the gateway, and did not reach the real service.
- `prompts/analyst.md`: one line explaining that a real-token event with `routed_to = "decoy"` or
  `"blocked"` means a human reviewer contained that credential+IP at our gateway.
No change to labels, validation, or scoring.

### E. Env (`env/seed.py`) — Renad's folder, change approved by Hadi (2026-10-25)

Add `(NPM_DECOY, DECOY_NPM_USER, "@kfu/build-utils", "9.9.10")` to `ATTACK_VERSIONS`, so a diverted
re-run of scenario 2 can publish 9.9.10 to the decoy again after `reset_packages`.

Also add the decoy 9.9.10 to the comment at the top of `env/reset_packages.sh`.

### G. Rehearsal reset (between runs)

1. `bash env/reset_packages.sh` (removes attack versions on real AND decoy, logs no events).
2. Empty the DB through a container (never from the host): the builder adds or reuses a small command
   that calls `common.db.reset()` without loading fixtures, e.g. `docker compose run --rm core python -m
   common.reset_db` (name left to the builder; must use `common/db.py`).

### F. Demo flow this enables

1. `normal.sh` → triage shows CI as Normal.
2. `scenario1.sh` → INC-001; "Nothing reached the real services".
3. `scenario2.sh` → INC-002; "Written to the real npm: @kfu/build-utils"; baseline vs observed;
   "Same credential elsewhere: 172.30.0.10, Normal".
4. Reviewer clicks **Divert to decoy**.
5. `scenario2.sh` again → its requests go to the decoy, join INC-002, response line shows N diverted.
6. `normal.sh` again → CI still installs from the real registry, still Normal, not in INC-002.

## Tests (numbers only from real runs)

- `tests/test_gateway_logic.py` / `test_gateway_addon.py`: block → 403 + `blocked` event; divert → decoy
  upstream + decoy auth + `decoy` event with `token_kind=real`; other IP with same credential unaffected;
  pending/rejected actions have no effect; lookup failure → 503.
- `tests/test_core.py`: `scope_ip` set on the first revoke action; a new-IP real event in an incident adds a
  second pending revoke; zero-hit real event from another IP does NOT join through credential match; all
  existing scenario expectations unchanged.
- `tests/test_dashboard.py`: decide_action block/divert/reject + guard; decided-line counts; the three
  panels incl. HTML escaping and the "nothing reached real" case.
- `common/db.py` migration: init on an old-schema DB adds the columns; running twice is harmless.
- Full suite green. Then a live run of the demo flow in Docker; `tests/sessions/check_scenarios.py` still
  passes for steps 1–3.

## Left to the builder

Exact CSS, wording polish, function names, query shapes, and whether the gateway caches the lookup.
Several processes call `db.init()` at startup at the same time: the `ALTER TABLE` migration must tolerate
"duplicate column" (another process won the race). "Same credential elsewhere" is for real credentials only.

## Calls made by Claude (check these)

- Kind name stays `revoke_credential`; only display text changes.
- One revoke prompt per (incident, credential, IP) with hits, at open and at join (B.2).
- Decisions are final; no undo for the demo.
- Old revoke rows without `scope_ip`: buttons disabled; fixture gets a `scope_ip`.
- Panel order: what reached real → baseline vs observed → same credential elsewhere → existing panels.
- Demo date is 2026-10-26 (moved after CLAUDE.md was written; Hadi said not to update CLAUDE.md for it).

# Ghostkey — ByteSentinels

Ghostkey turns the use of bait keys inside our own Git + package registry into ONE incident story
(source, then build, then publish) with evidence, so a small security team can investigate and respond faster.

Everything the team needs (contracts, rules, ownership, expected demo results) is in **CLAUDE.md**.
Claude Code reads it automatically when you run `claude` in this folder. If this README and CLAUDE.md disagree, CLAUDE.md wins.

## 1. Setup

You need Docker Desktop. On Windows, run the `bash` commands in Git Bash.

```bash
cp .env.example .env                           # setup.sh does this too if .env is missing
docker compose pull                            # do this once, on good wifi
bash env/setup.sh                              # starts the 4 Gitea/Verdaccio services, creates users, plants baits,
                                               # seeds packages, writes DECOY_* into .env
bash env/verify.sh                             # optional: PASS/FAIL check of the seeded environment
docker compose up -d --build                   # gateway, core, brain, dashboard, ci-runner, attacker, attacker2
docker compose up -d --force-recreate gateway  # only if the gateway was already running before setup.sh
```

- `setup.sh` is safe to run again. It keeps existing users, repos, packages and tokens.
- The LLM is optional. Leave `LLM_*` empty in `.env` and the analyst uses rules only. The system works fully without it.
- Dashboard: http://localhost:8501
- More detail on the seeded data: `env/README.md`.

## 2. Run the scenarios

Run them in this order. Each script pauses 2 seconds between steps so the dashboard visibly updates
(change it with `DEMO_PAUSE=<seconds>`).

### Normal traffic

```bash
docker compose exec ci-runner bash /work/normal.sh
```

The CI runner (172.30.0.10) uses `REAL-CI-01` as usual: `npm whoami`, then installs `@kfu/build-utils`.
Expect: zero signals and zero incidents. The events show up in the traffic triage panel, but nothing is flagged.

Every client script starts with a short countdown (`DEMO_START_DELAY`, default 3 seconds) so you can switch to the dashboard. `run_all.sh` skips it.
To run everything in the final order (normal, noise, scenarios 1 to 4) from the host:

```bash
bash attacker/run_all.sh
```

Each scenario uses its own client IP and its own bait. If two scenarios shared an IP or a bait, core would merge them into one incident.

### Scenario 1: leaked bait

```bash
docker compose exec attacker bash /work/scenario1.sh
```

The attacker (172.30.0.66) finds a leaked `.env` with `BAIT-SRC-01`, then:
lists repos, clones `ops/ci-pipeline` (decoy), finds `BAIT-CI-02` in its `.npmrc`, runs `npm whoami`, and publishes `@kfu/build-utils@9.9.9`.

Expect on the dashboard:
- exactly 1 incident, `signal_kind=bait`, `confidence=high`, score 95 (60+20+15), severity `critical`
- stages `source` then `build`
- every event `routed_to=decoy`, zero events to real
- actions: one `notify` done, one `disable_bait` done per bait
- the analyst lists `automated_secret_scanner` as an alternative

### Scenario 2: stolen real credential (no bait)

```bash
docker compose exec attacker2 bash /work/scenario2.sh
```

The attacker (172.30.0.77) uses `REAL-CI-01` (the `ci-bot` npm token) from a new machine:
installs `@kfu/build-utils`, installs `@kfu/payments-sdk`, then tries to publish `@kfu/build-utils@9.9.10`.
The real registry only lets `release-bot` publish, so the publish is refused (403). Ghostkey still sees and scores the attempt.

Expect on the dashboard:
- 1 incident, `signal_kind=behavior`, `confidence=medium`, score 80 (20+25+35), severity `high`, status `needs_review`
- every event `routed_to=real` (no bait was used, so nothing is diverted at first); the publish event has `result=denied`
- actions: one `notify` done, one `revoke_credential` **pending**

**The reviewer step.** `revoke_credential` is never automatic. A human decides on the dashboard:
- **Block**: our gateway answers 403 to this credential from this IP. Events show `routed_to=blocked`.
- **Divert to decoy**: our gateway sends this credential from this IP to the decoy services. Events show `routed_to=decoy`.
- **Reject**: nothing changes.

The decision applies only to that credential from that IP (here `REAL-CI-01` from 172.30.0.77), and only at OUR gateway.
Nothing is changed on Gitea or Verdaccio. After you decide, the dashboard shows how many requests were really stopped or diverted.

To see the effect, reset the packages (section 4), then run Scenario 2 again.
The new requests from 172.30.0.77 are now blocked or diverted. The normal CI runner (172.30.0.10) is not affected.
Scenario 3 publishes `@kfu/payments-sdk@6.6.6` to the decoy registry; `reset_packages.sh` removes it too.
Note: on the real registry the scenario 2 publish is refused, so nothing is written there. A diverted re-run succeeds on the decoy
and publishes `@kfu/build-utils@9.9.10` there. `reset_packages.sh` removes it.

### Scenario 3: leaked publish script

```bash
docker compose exec attacker3 bash /work/scenario3.sh
```

The attacker (172.30.0.88) has a copy of `ops/release-tools/scripts/publish.sh` with `BAIT-PUB-03`:
`npm whoami`, `npm search @kfu`, installs `@kfu/payments-sdk`, then publishes `@kfu/payments-sdk@6.6.6`.

Expect: 1 incident, `signal_kind=bait`, `confidence=high`, score 75 (60+15), severity `high`, stages `publish` only,
every event `routed_to=decoy`, one `notify` done, one `disable_bait` done for `BAIT-PUB-03`, hypothesis `package_publish`.

### Scenario 4: scanner with a leaked doc token

```bash
docker compose exec attacker4 bash /work/scenario4.sh
```

The attacker (172.30.0.99, user agent `ghostkey-demo-scanner/1.0`) found `BAIT-DOC-04` in the `dev/docs` deploy runbook
and only reads through the Gitea API: `user`, `user/repos`, `repos/search`, a README. No clone, no push, no npm.

Expect: 1 incident, `signal_kind=bait`, `confidence=high`, score 60, severity `medium`, stages `source` only,
every event `routed_to=decoy`, one `notify` done, one `disable_bait` done for `BAIT-DOC-04`,
hypothesis `recon_only`, and `automated_secret_scanner` as an alternative.

`BAIT-DOC-04` lives in the real Gitea repo `dev/docs`. After you pull this change, run `bash env/setup.sh` once
(it plants the bait and writes the loot files), then restart the gateway so it loads the new bait:
`docker compose up -d --force-recreate gateway`. Then `docker compose up -d` creates the new client containers.

### Background noise

```bash
docker compose exec dev-laptop bash /work/noise.sh
```

The dev laptop (172.30.0.50) sends ordinary traffic: an anonymous Gitea search, an anonymous npm install (refused),
and one Gitea request with a mistyped token (`token_kind=unknown`).
Expect: zero signals and zero incidents. The events show up in the traffic panel only.

## 3. Check the results

After running all the scripts (or `run_all.sh`), check the acceptance results against the live DB:

```bash
docker compose run --rm --no-deps core python -m tests.sessions.check_scenarios
```

It prints the events table for each client and PASS/FAIL per check, and exits with 1 if any check failed.
It checks the state from the first run, so run it before you make a Block/Divert decision.

Unit tests (they run inside the image, so rebuild after code changes):

```bash
docker compose build core
docker compose run --rm --no-deps core python -m unittest discover -s tests -t .
```

## 4. Reset between runs and watch logs

Before you run a scenario again, remove the packages it published (this goes straight to the registries and logs no events):

```bash
bash env/reset_packages.sh
```

Clear old incidents and events from the dashboard (empties every table in `ghostkey.db`):

```bash
docker compose run --rm --no-deps core python -m common.reset_db
```

For a full clean slate you can instead stop gateway, core, brain and dashboard, then `docker volume rm ghostkey_gkdata`.
Do not delete the `verdaccio_*` volumes unless you run `bash env/setup.sh` again and recreate the gateway.

Logs:

```bash
docker compose logs -f gateway core brain
```

## 5. Development only: no gateway

You can work on core, brain and the dashboard with fixture events instead of live traffic:

```bash
docker compose run --rm core python -m fixtures.load_fixtures --reset
```

`--reset` empties the DB first. You can also pass one fixture name: `normal`, `scenario1` or `scenario2`.

```bash
docker compose run --rm core python -m fixtures.load_fixtures --reset --fake-core
```

**`--fake-core` is DEVELOPMENT ONLY.** It writes the expected incidents, signals, analyses and actions directly.
Never use it in the demo, and never when testing core or brain.

## 6. Safety

- Every token, password and package here is synthetic. Never commit `.env`, `data/` or `attacker/.secrets/`.
- All attack activity runs only inside our own Docker networks. Never point the scripts at GitHub.com, npmjs.com or any system we do not own.
- `realnet` and `decoynet` are `internal: true`: the real and decoy services have no internet. Do not add egress.
- Routing happens only at OUR gateway, in front of OUR services. Ghostkey never changes external systems.

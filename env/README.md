# env/ — demo environment (Gitea + Verdaccio, real and decoy)

Everything here is synthetic and runs only inside Docker. No internet is used.

## From a clean machine to "ready"

```bash
cp .env.example .env              # setup.sh does this too if .env is missing
docker compose pull               # good wifi, once
bash env/setup.sh                 # start 4 services, create users, plant baits, seed packages, write DECOY_* into .env
bash env/verify.sh                # optional: PASS/FAIL checks, no gateway needed
docker compose up -d --build      # gateway, core, brain, dashboard, ci-runner, attacker, attacker2
docker compose up -d --force-recreate gateway   # only if the gateway was already running before setup
```

`setup.sh` is safe to run again. It keeps existing users, repos, packages and tokens.
It writes: `.env` (only the 3 DECOY_* lines), `contracts/credentials.json` (hash of REAL-CI-01),
`attacker/loot/payments-api.env` (the "leaked" copy of the planted `.env`),
`attacker/loot/docs-deploy.md` (the "leaked" copy of the `dev/docs` deploy runbook with BAIT-DOC-04),
and `attacker/.secrets/real-ci-01.token` (gitignored).

## Run the scenarios

```bash
docker compose exec ci-runner bash /work/normal.sh      # normal traffic, no incident
docker compose exec attacker  bash /work/scenario1.sh   # leaked bait
docker compose exec attacker2 bash /work/scenario2.sh   # stolen real credential
docker compose exec attacker3 bash /work/scenario3.sh   # leaked publish script (BAIT-PUB-03)
docker compose exec attacker4 bash /work/scenario4.sh   # scanner with BAIT-DOC-04, read-only
docker compose exec dev-laptop bash /work/noise.sh      # anonymous and mistyped requests, no incident
bash attacker/run_all.sh                                # all of the above in order
bash env/reset_packages.sh                              # before running a scenario again
```

`reset_packages.sh` removes `@kfu/build-utils@9.9.9` and `@kfu/build-utils@9.9.10` (decoy registry; the latter only exists after a
diverted scenario 2 re-run) directly on the registries, so it creates no events. It also tries to remove 9.9.10 from the real
registry, which only matters if an older run (before publish was limited to `release-bot`) left it there.
Old incidents stay in the dashboard until you clear the DB (stop gateway/core/brain/dashboard, then `docker volume rm ghostkey_gkdata`).

## What is where

| What | Where |
|---|---|
| Real Gitea: org `dev` (`payments-api` has the planted `.env` with BAIT-SRC-01, `docs` has `runbooks/deploy.md` with BAIT-DOC-04) | `gitea-real`, user `dev-lead` |
| Decoy Gitea: `ops/ci-pipeline` (`.npmrc` has BAIT-CI-02), `ops/release-tools` (`scripts/publish.sh` has BAIT-PUB-03) | `gitea-decoy`, user `ci-mirror` (= `DECOY_GIT_USER`) |
| Real Verdaccio: `ci-bot` (token = REAL-CI-01), `release-bot` | `verdaccio-real` |
| Decoy Verdaccio: `registry-mirror` (token = `DECOY_NPM_TOKEN`) | `verdaccio-decoy` |
| Packages (both registries, zero dependencies) | `@kfu/build-utils@1.4.2`, `@kfu/payments-sdk@2.1.0` |

Files: `setup.sh` (entry point), `seed.py` (steps), `seed_gitea.py`, `seed_verdaccio.py`, `seed_content.py` (fake files),
`http_util.py`, `verify.py` / `verify.sh`, `reset_packages.sh`, `verdaccio/{real,decoy}/config.yaml`.
The seed code runs in a one-off `setup` container (compose profile `setup`, on realnet + decoynet only).

## Notes

- The demo accounts share one synthetic password (`SEED_PASSWORD`, default in `setup.sh`). Both registries are internal-only.
- `@kfu/*` and everything else needs a valid token (`access: $authenticated`). Anonymous reads get 401.
- Verdaccio has no uplinks and no proxy lines. Tokens live in the storage volumes: do not delete `verdaccio_*` volumes
  without running `setup.sh` again and restarting the gateway (REAL-CI-01 changes).
- Git Bash on Windows: the scripts set `MSYS_NO_PATHCONV=1` so docker arguments like `/repo` are not rewritten.

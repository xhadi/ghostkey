#!/usr/bin/env bash
# Remove the versions the scenarios publish, so you can run them again:
#   @kfu/build-utils@9.9.9 and (after a diverted scenario 2 re-run) @kfu/build-utils@9.9.10 on the DECOY registry,
#   @kfu/build-utils@9.9.10 on the REAL one (normally absent: only release-bot may publish there, so scenario 2 is refused),
#   @kfu/payments-sdk@6.6.6 on the DECOY registry (scenario 3).
# Goes straight to the registries (not through the gateway), so it logs no events.
set -euo pipefail

cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'
export SEED_PASSWORD="${SEED_PASSWORD:-ghostkey-demo-pass}"

docker compose run --rm -T -e SEED_PASSWORD setup python3 -u -m env.seed reset-packages

#!/usr/bin/env bash
# Remove the versions the scenarios publish, so you can run them again:
#   @kfu/build-utils@9.9.9 on the DECOY registry, @kfu/build-utils@9.9.10 on the REAL one.
# Goes straight to the registries (not through the gateway), so it logs no events.
set -euo pipefail

cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'
export SEED_PASSWORD="${SEED_PASSWORD:-ghostkey-demo-pass}"

docker compose run --rm -T -e SEED_PASSWORD setup python3 -u -m env.seed reset-packages

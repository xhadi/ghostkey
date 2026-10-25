#!/usr/bin/env bash
# Check the seeded environment without the gateway. Run after: bash env/setup.sh
set -euo pipefail

cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'
export SEED_PASSWORD="${SEED_PASSWORD:-ghostkey-demo-pass}"

docker compose run --rm -T -e SEED_PASSWORD setup python3 -u -m env.verify

echo "Registry logs (neither registry may try to reach npmjs):"
if docker compose logs --no-color verdaccio-real verdaccio-decoy 2>&1 | grep -qi "registry.npmjs"; then
  echo "  FAIL  found a registry.npmjs.org mention in the Verdaccio logs"
  exit 1
fi
echo "  PASS  no registry.npmjs.org in the Verdaccio logs"

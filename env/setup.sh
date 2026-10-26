#!/usr/bin/env bash
# One-command setup for the Ghostkey demo environment. Safe to run again.
#
#   bash env/setup.sh
#
# It starts Gitea + Verdaccio (real and decoy), creates the demo accounts,
# plants the baits, seeds packages, and writes DECOY_* into .env.
# Needs: Docker Desktop. Run from any folder.
set -euo pipefail

cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1          # Git Bash on Windows must not rewrite /paths in docker args
export MSYS2_ARG_CONV_EXCL='*'

# Synthetic password for the demo accounts. Both registries are internal-only.
export SEED_PASSWORD="${SEED_PASSWORD:-ghostkey-demo-pass}"

SERVICES="gitea-real gitea-decoy verdaccio-real verdaccio-decoy"
seed() { docker compose run --rm -T -e SEED_PASSWORD setup python3 -u -m env.seed "$@"; }

# Create a Gitea user with the gitea CLI unless it already exists.
ensure_gitea_user() {
  local service="$1" user="$2"
  if docker compose exec -T -u git "$service" gitea admin user list | grep -qw "$user"; then
    echo "  $service: user $user already exists"
  else
    docker compose exec -T -u git "$service" gitea admin user create \
      --username "$user" --password "$SEED_PASSWORD" --email "$user@kfu.example" \
      --admin --must-change-password=false >/dev/null
    echo "  $service: user $user created"
  fi
}

if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example"
fi

echo "[1/4] Starting services..."
docker compose up -d $SERVICES
seed wait

echo "[2/4] Creating Gitea users..."
ensure_gitea_user gitea-real dev-lead
ensure_gitea_user gitea-decoy ci-mirror

echo "[3/4] Seeding repos, packages, baits..."
seed all

echo "[4/4] Summary"
echo "  real  Gitea    : org dev (payments-api with planted BAIT-SRC-01, student-portal, docs with BAIT-DOC-04 in runbooks/deploy.md)"
echo "  decoy Gitea    : org ops (ci-pipeline with BAIT-CI-02, release-tools with BAIT-PUB-03), org dev"
echo "  real  Verdaccio: users ci-bot (token = REAL-CI-01), release-bot; @kfu/build-utils, @kfu/payments-sdk"
echo "  decoy Verdaccio: user registry-mirror; same two packages"
echo "  .env           : DECOY_GIT_USER, DECOY_GIT_TOKEN, DECOY_NPM_TOKEN updated"
echo "  credentials    : contracts/credentials.json now has the hash of REAL-CI-01"
echo "  secrets        : attacker/.secrets/real-ci-01.token (gitignored)"
echo "Next: restart the gateway so it reloads these:  docker compose up -d --force-recreate gateway"

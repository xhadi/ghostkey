#!/usr/bin/env bash
# Run the demo client scripts one after another, from the host:
#   bash attacker/run_all.sh
# Each script counts down before its first request (DEMO_START_DELAY, default 3).
set -euo pipefail

cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1          # Git Bash on Windows must not rewrite /paths in docker args

docker compose exec -T ci-runner bash /work/normal.sh
docker compose exec -T dev-laptop bash /work/noise.sh
docker compose exec -T attacker bash /work/scenario1.sh
docker compose exec -T attacker2 bash /work/scenario2.sh
docker compose exec -T attacker3 bash /work/scenario3.sh
docker compose exec -T attacker4 bash /work/scenario4.sh

echo
echo "All done. Check the dashboard: http://localhost:8501"

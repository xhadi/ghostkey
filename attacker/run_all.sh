#!/usr/bin/env bash
# Run the demo client scripts one after another, from the host:
#   bash attacker/run_all.sh
# No start countdown here (DEMO_START_DELAY=0); run a single script on its own to get the 3 s countdown.
set -euo pipefail

cd "$(dirname "$0")/.."
export MSYS_NO_PATHCONV=1          # Git Bash on Windows must not rewrite /paths in docker args
RUN="docker compose exec -T -e DEMO_START_DELAY=0"

$RUN ci-runner bash /work/normal.sh
$RUN dev-laptop bash /work/noise.sh
$RUN attacker bash /work/scenario1.sh
$RUN attacker2 bash /work/scenario2.sh
$RUN attacker3 bash /work/scenario3.sh
$RUN attacker4 bash /work/scenario4.sh

echo
echo "All done. Check the dashboard: http://localhost:8501"

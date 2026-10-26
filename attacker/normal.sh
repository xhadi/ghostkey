#!/usr/bin/env bash
# Normal traffic: the CI runner (172.30.0.10) with REAL-CI-01 does its usual job.
# Everything here is in the credential's baseline, so it must raise no signal.
#   docker compose exec ci-runner bash /work/normal.sh
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

intro "Normal CI traffic"

load_ci_token
make_workdir
write_npmrc "$CI_TOKEN"

step 1 2 "CI job: checking the registry login (npm whoami)"
run_npm whoami --registry "$NPM_URL" | sed 's/^/    /'
pause

step 2 2 "CI job: installing @kfu/build-utils"
install_package "@kfu/build-utils"

echo
echo "Done. Check the dashboard: no new incident."

#!/usr/bin/env bash
# Scenario 2: a stolen REAL credential, no bait (attacker container 172.30.0.77).
# The attacker uses ci-bot's npm token (REAL-CI-01) from a new machine.
#   docker compose exec attacker2 bash /work/scenario2.sh
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

intro "Scenario 2: stolen real credential"

load_ci_token
make_workdir
write_npmrc "$CI_TOKEN"

step 1 3 "Installing @kfu/build-utils with the stolen CI token (from a new machine)"
install_package "@kfu/build-utils"
pause

step 2 3 "Installing @kfu/payments-sdk (a package this token never used before)"
install_package "@kfu/payments-sdk"
pause

step 3 3 "Publishing @kfu/build-utils@9.9.10 (this token never publishes)"
make_package "$WORK/tampered" "@kfu/build-utils" "9.9.10"
(cd "$WORK/tampered" && run_npm publish --registry "$NPM_URL") | sed 's/^/    /'

echo
echo "Done. Check the dashboard: one behavior incident (needs review)."

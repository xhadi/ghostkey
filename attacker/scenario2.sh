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
# The real registry only lets release-bot publish, so this is normally refused. Do not let that abort the script.
# If a reviewer chose Divert, the same publish goes to the decoy and succeeds.
if (cd "$WORK/tampered" && run_npm publish --registry "$NPM_URL") > "$WORK/publish.log" 2>&1; then
  sed 's/^/    /' "$WORK/publish.log"
  echo "    publish succeeded (it was not refused, e.g. a reviewer diverted it to the decoy)"
else
  sed 's/^/    /' "$WORK/publish.log"
  echo "    publish refused by the registry (expected: ci-bot may not publish)"
fi

echo
echo "Done. Check the dashboard: one behavior incident (needs review)."

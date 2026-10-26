#!/usr/bin/env bash
# Background noise: ordinary traffic that must NOT raise anything (dev laptop 172.30.0.50).
# No bait and no real credential is used, so core must open no incident and count no signal.
#   docker compose exec dev-laptop bash /work/noise.sh
set -euo pipefail
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

intro "Background noise: anonymous and mistyped requests"

# A made-up 40-hex string. It is not in contracts/baits.json and not a real credential.
MISTYPED_TOKEN="9142fe3495c00214d3f826c059931f6147e8ee32"
make_workdir

step 1 3 "Searching Gitea repos without any token"
# The server may answer 200 or 401. Both are fine, so a failure must not stop the script.
curl -sS -o /dev/null -w "    HTTP %{http_code}\n" "$GIT_URL/api/v1/repos/search" || true
pause

step 2 3 "Installing @kfu/build-utils without any token (expected to be refused)"
# A config with no auth token at all: only the registry address.
NPMRC="$WORK/npmrc"
NPM_CACHE="$WORK/npm-cache"
printf 'registry=%s\nupdate-notifier=false\naudit=false\nfund=false\n' "$NPM_URL" > "$NPMRC"
install_package "@kfu/build-utils" || echo "    refused, as expected for an anonymous user"
pause

step 3 3 "Listing repos with a mistyped token"
curl -sS -o /dev/null -w "    HTTP %{http_code}\n" \
  -H "Authorization: token $MISTYPED_TOKEN" "$GIT_URL/api/v1/user/repos" || true

echo
echo "Done. Check the dashboard: no new incident."

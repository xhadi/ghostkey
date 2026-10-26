#!/usr/bin/env bash
# Shared helpers for the demo client scripts. Sourced, not run.
# All traffic goes to the gateway only: git on :8080, npm on :8081.

GIT_URL="http://gateway:8080"
NPM_URL="http://gateway:8081/"
NPM_HOST_PATH="//gateway:8081/"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PAUSE_SECONDS="${DEMO_PAUSE:-2}"   # so the dashboard visibly updates between steps
START_DELAY="${DEMO_START_DELAY:-3}"   # time to switch to the dashboard before the first request

die() {
  echo "ERROR: $*" >&2
  exit 1
}

# intro <title>: print the title, then count down so the presenter can open the dashboard.
intro() {
  local seconds="$START_DELAY"
  echo "=== $1 ==="
  printf "Starting in"
  while [ "$seconds" -gt 0 ]; do
    printf " %s..." "$seconds"
    sleep 1
    seconds=$((seconds - 1))
  done
  echo " go"
}

# step <n> <total> <text>
step() {
  echo
  echo "[$1/$2] $3"
}

pause() {
  sleep "$PAUSE_SECONDS"
}

# Make a temp working folder; it is removed when the script ends.
make_workdir() {
  WORK="$(mktemp -d)"
  trap 'rm -rf "$WORK"' EXIT
}

# Read the real-ci-01 token written by env/setup.sh.
load_ci_token() {
  local file="$HERE/.secrets/real-ci-01.token"
  [ -s "$file" ] || die "$file is missing. Run 'bash env/setup.sh' on the host first."
  CI_TOKEN="$(tr -d '\r\n' < "$file")"
}

# Write a throwaway npm config for this token. Sets NPMRC and NPM_CACHE.
# The extra settings stop npm from making requests we do not want to log
# (update check, audit, funding).
write_npmrc() {
  local token="$1"
  NPMRC="$WORK/npmrc"
  NPM_CACHE="$WORK/npm-cache"
  cat > "$NPMRC" <<RC
registry=$NPM_URL
${NPM_HOST_PATH}:_authToken=$token
update-notifier=false
audit=false
fund=false
RC
}

# Run npm with the throwaway config. Quiet output, no audit, fresh cache.
run_npm() {
  npm --userconfig "$NPMRC" --cache "$NPM_CACHE" --no-update-notifier --no-audit --no-fund --loglevel=warn "$@"
}

# Create a tiny package folder: make_package <dir> <name> <version>
make_package() {
  local dir="$1" name="$2" version="$3"
  mkdir -p "$dir"
  cat > "$dir/package.json" <<JSON
{
  "name": "$name",
  "version": "$version",
  "description": "build helpers",
  "main": "index.js",
  "license": "UNLICENSED"
}
JSON
  echo "module.exports = { name: '$name', version: '$version' };" > "$dir/index.js"
}

# Install one package in a fresh empty project folder: install_package <name>
install_package() {
  local name="$1" dir
  dir="$(mktemp -d -p "$WORK")"
  echo '{ "name": "demo-project", "version": "1.0.0", "private": true }' > "$dir/package.json"
  (cd "$dir" && run_npm install "$name") | sed '/^$/d; s/^/    /'
}

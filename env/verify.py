"""Check the seeded environment WITHOUT the gateway. Runs inside the `setup` container.

Usage: python3 -u -m env.verify      (normally via: bash env/verify.sh)
Prints PASS/FAIL lines. Never prints a token.
"""
from __future__ import annotations

import hashlib
import json
import sys
from urllib.parse import quote, urlsplit

from env import seed
from env import seed_content as content
from env.http_util import request
from env import seed_verdaccio as verdaccio

failures: list[str] = []


def check(ok: bool, label: str) -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}")
    if not ok:
        failures.append(label)


def raw_file(base: str, repo: str, path: str, auth: str) -> str:
    status, body = request("GET", f"{base}/api/v1/repos/{repo}/raw/{path}?ref=main", token_header=auth)
    return body if status == 200 and isinstance(body, str) else ""


def check_decoy_gitea() -> None:
    print("Decoy Gitea (decoy token):")
    auth = f"token {seed.read_env_value('DECOY_GIT_TOKEN')}"
    status, repos = request("GET", f"{seed.GITEA_DECOY}/api/v1/user/repos", token_header=auth)
    names = sorted(r["full_name"] for r in repos) if status == 200 else []
    print(f"        repos: {', '.join(names)}")
    check("ops/ci-pipeline" in names and "ops/release-tools" in names, "GET /api/v1/user/repos lists ops/ci-pipeline and ops/release-tools")
    npmrc = raw_file(seed.GITEA_DECOY, "ops/ci-pipeline", ".npmrc", auth)
    check(content.bait_token("BAIT-CI-02") in npmrc and "//gateway:8081/:_authToken=" in npmrc, "ops/ci-pipeline/.npmrc holds BAIT-CI-02 (registry gateway:8081)")
    publish = raw_file(seed.GITEA_DECOY, "ops/release-tools", "scripts/publish.sh", auth)
    check(content.bait_token("BAIT-PUB-03") in publish, "ops/release-tools/scripts/publish.sh holds BAIT-PUB-03")
    status, _ = request("GET", f"{seed.GITEA_DECOY}/api/v1/user", token_header=f"token {content.bait_token('BAIT-SRC-01')}")
    check(status == 401, "the bait string itself is not valid on the decoy Gitea")


def check_real_gitea() -> None:
    print("Real Gitea:")
    basic = (seed.REAL_GIT_USER, seed.password())
    status, body = request("GET", f"{seed.GITEA_REAL}/api/v1/repos/dev/payments-api/raw/.env?ref=main", basic=basic)
    check(status == 200 and f"GITEA_TOKEN={content.bait_token('BAIT-SRC-01')}" in str(body), "dev/payments-api/.env holds BAIT-SRC-01")
    status, _ = request("GET", f"{seed.GITEA_REAL}/api/v1/user", token_header=f"token {content.bait_token('BAIT-SRC-01')}")
    check(status == 401, "the bait string itself is not valid on the real Gitea")
    check(seed.LOOT_FILE.read_text() == content.payments_env_file(seed.REAL_GIT_USER), "attacker/loot/payments-api.env matches the planted .env")


def tarball_status(base: str, token: str, package: str) -> int:
    """Fetch the newest tarball. dist.tarball points at the gateway, so swap in the internal host."""
    packument = verdaccio.get_packument(base, token, package) or {}
    latest = packument.get("dist-tags", {}).get("latest", "")
    url = packument.get("versions", {}).get(latest, {}).get("dist", {}).get("tarball", "")
    internal = urlsplit(base)
    parts = urlsplit(url)
    status, _ = request("GET", parts._replace(scheme=internal.scheme, netloc=internal.netloc).geturl(), token_header=f"Bearer {token}")
    return status


def check_registry(label: str, base: str, user: str, token: str) -> None:
    print(f"{label} Verdaccio ({user} token, Authorization: Bearer):")
    check(verdaccio.whoami(base, token) == user, f"GET /-/whoami returns {user}")
    for package, version, _ in content.SEED_PACKAGES:
        check(version in verdaccio.versions_of(base, token, package), f"{package}@{version} is published")
        check(tarball_status(base, token, package) == 200, f"{package} tarball downloads")
    status, _ = request("GET", f"{base}/{quote('@kfu/build-utils', safe='@')}")
    check(status == 401, "anonymous read of @kfu/build-utils is refused (401)")
    packument = verdaccio.get_packument(base, token, "@kfu/build-utils") or {}
    deps = [v.get("dependencies") for v in packument.get("versions", {}).values()]
    check(not any(deps), "@kfu/build-utils has zero dependencies")
    bait_status = verdaccio.whoami(base, content.bait_token("BAIT-CI-02"))
    check(bait_status is None, "the bait string itself is not valid on this registry")


def check_credentials_file() -> None:
    print("REAL-CI-01:")
    token = seed.read_ci_bot_token()
    creds = json.loads((seed.ROOT / "contracts" / "credentials.json").read_text(encoding="utf-8"))
    stored = next((c["sha256"] for c in creds if c["credential_id"] == "REAL-CI-01"), "")
    check(bool(token) and stored == hashlib.sha256(token.encode()).hexdigest(), "contracts/credentials.json hash matches attacker/.secrets/real-ci-01.token")


def main() -> None:
    check_decoy_gitea()
    check_real_gitea()
    check_registry("Real", seed.NPM_REAL, "ci-bot", seed.read_ci_bot_token())
    check_registry("Decoy", seed.NPM_DECOY, seed.DECOY_NPM_USER, seed.read_env_value("DECOY_NPM_TOKEN"))
    check_credentials_file()
    if failures:
        sys.exit(f"\n{len(failures)} check(s) failed")
    print("\nAll checks passed.")


if __name__ == "__main__":
    main()

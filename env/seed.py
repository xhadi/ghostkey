"""Seed the Ghostkey demo environment over HTTP. Runs inside the `setup` container.

Usage (normally started by env/setup.sh):
    python3 -u -m env.seed wait            # wait until all four services answer
    python3 -m env.seed all             # seed Gitea + Verdaccio, write .env / secrets / credentials.json
    python3 -m env.seed reset-packages  # remove the attack versions (9.9.9 on decoy, 9.9.10 on real)

Needs the env var SEED_PASSWORD (a synthetic password for the demo accounts).
Nothing here prints a token or a password.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

from env import seed_content as content
from env import seed_gitea as gitea
from env import seed_verdaccio as verdaccio
from env.http_util import wait_until_ready

ROOT = Path(__file__).resolve().parent.parent
ENV_FILE = ROOT / ".env"
SECRETS_DIR = ROOT / "attacker" / ".secrets"
CI_BOT_TOKEN_FILE = SECRETS_DIR / "real-ci-01.token"
LOOT_FILE = ROOT / "attacker" / "loot" / "payments-api.env"
DOCS_LOOT_FILE = ROOT / "attacker" / "loot" / "docs-deploy.md"
PUBLISH_LOOT_FILE = ROOT / "attacker" / "loot" / "release-publish.sh"

GITEA_REAL = "http://gitea-real:3000"
GITEA_DECOY = "http://gitea-decoy:3000"
NPM_REAL = "http://verdaccio-real:4873"
NPM_DECOY = "http://verdaccio-decoy:4873"

REAL_GIT_USER = "dev-lead"
DECOY_GIT_USER = "ci-mirror"
DECOY_NPM_USER = "registry-mirror"

# Versions created by the attack scenarios; reset_packages removes them.
ATTACK_VERSIONS = [
    (NPM_DECOY, DECOY_NPM_USER, "@kfu/build-utils", "9.9.9"),
    (NPM_DECOY, DECOY_NPM_USER, "@kfu/build-utils", "9.9.10"),  # a diverted scenario 2 re-run
    (NPM_REAL, "release-bot", "@kfu/build-utils", "9.9.10"),
    (NPM_DECOY, DECOY_NPM_USER, "@kfu/payments-sdk", "6.6.6"),     # scenario 3
]


# --- .env helpers (values are never printed) ---------------------------------

def read_env_value(key: str) -> str:
    if not ENV_FILE.exists():
        return ""
    for line in ENV_FILE.read_text(encoding="utf-8").splitlines():
        if line.startswith(key + "="):
            return line.split("=", 1)[1].strip()
    return ""


def update_env(values: dict[str, str]) -> None:
    """Set KEY=value lines in .env. Every other line stays exactly as it is."""
    raw = ENV_FILE.read_bytes().decode("utf-8") if ENV_FILE.exists() else ""
    newline = "\r\n" if "\r\n" in raw else "\n"
    lines = raw.splitlines()
    pending = dict(values)
    for index, line in enumerate(lines):
        key = line.split("=", 1)[0]
        if "=" in line and not line.startswith("#") and key in pending:
            lines[index] = f"{key}={pending.pop(key)}"
    for key, value in pending.items():
        lines.append(f"{key}={value}")
    ENV_FILE.write_bytes((newline.join(lines) + newline).encode("utf-8"))


def password() -> str:
    value = os.environ.get("SEED_PASSWORD", "")
    if not value:
        raise SystemExit("SEED_PASSWORD is not set. Run this through: bash env/setup.sh")
    return value


# --- steps -------------------------------------------------------------------

def wait_for_services() -> None:
    print("Waiting for services...")
    wait_until_ready(f"{GITEA_REAL}/api/healthz", "gitea-real")
    wait_until_ready(f"{GITEA_DECOY}/api/healthz", "gitea-decoy")
    wait_until_ready(f"{NPM_REAL}/-/ping", "verdaccio-real")
    wait_until_ready(f"{NPM_DECOY}/-/ping", "verdaccio-decoy")


def seed_real_gitea() -> None:
    print("Real Gitea:")
    pw = password()
    gitea.seed_repos(GITEA_REAL, REAL_GIT_USER, pw, content.real_repos(REAL_GIT_USER))
    LOOT_FILE.parent.mkdir(parents=True, exist_ok=True)
    LOOT_FILE.write_text(content.payments_env_file(REAL_GIT_USER), encoding="utf-8")
    DOCS_LOOT_FILE.write_text(content.deploy_runbook(), encoding="utf-8")
    print(f"  attacker loot copies written: {LOOT_FILE.relative_to(ROOT)}, {DOCS_LOOT_FILE.relative_to(ROOT)}")


def seed_decoy_gitea() -> None:
    print("Decoy Gitea:")
    pw = password()
    token = gitea.ensure_token(GITEA_DECOY, DECOY_GIT_USER, pw, "ghostkey-decoy", read_env_value("DECOY_GIT_TOKEN"))
    gitea.seed_repos(GITEA_DECOY, DECOY_GIT_USER, pw, content.decoy_repos(DECOY_GIT_USER))
    PUBLISH_LOOT_FILE.write_text(content.release_publish_script(), encoding="utf-8")
    print(f"  attacker loot copy written: {PUBLISH_LOOT_FILE.relative_to(ROOT)}")
    update_env({"DECOY_GIT_USER": DECOY_GIT_USER, "DECOY_GIT_TOKEN": token})
    print("  DECOY_GIT_USER / DECOY_GIT_TOKEN written to .env")


def keep_or_login(base: str, user: str, pw: str, current: str) -> str:
    """Reuse `current` if it still works for `user` (so tokens do not change on every run)."""
    if current and verdaccio.whoami(base, current) == user:
        return current
    return verdaccio.ensure_user(base, user, pw)


def read_ci_bot_token() -> str:
    return CI_BOT_TOKEN_FILE.read_text(encoding="utf-8").strip() if CI_BOT_TOKEN_FILE.exists() else ""


def seed_real_verdaccio() -> None:
    print("Real Verdaccio:")
    pw = password()
    tokens = {
        "ci-bot": keep_or_login(NPM_REAL, "ci-bot", pw, read_ci_bot_token()),
        "release-bot": verdaccio.ensure_user(NPM_REAL, "release-bot", pw),
    }
    for package, version, description in content.SEED_PACKAGES:
        verdaccio.publish_package(NPM_REAL, tokens["release-bot"], package, version, description)
    SECRETS_DIR.mkdir(parents=True, exist_ok=True)
    CI_BOT_TOKEN_FILE.write_text(tokens["ci-bot"] + "\n", encoding="utf-8")
    subprocess.run([sys.executable, "-m", "env.register_credential", "REAL-CI-01", tokens["ci-bot"]],
                   cwd=ROOT, check=True)
    print(f"  ci-bot token saved to {CI_BOT_TOKEN_FILE.relative_to(ROOT)} (gitignored)")


def seed_decoy_verdaccio() -> None:
    print("Decoy Verdaccio:")
    pw = password()
    token = keep_or_login(NPM_DECOY, DECOY_NPM_USER, pw, read_env_value("DECOY_NPM_TOKEN"))
    for package, version, description in content.SEED_PACKAGES:
        verdaccio.publish_package(NPM_DECOY, token, package, version, description)
    update_env({"DECOY_NPM_TOKEN": token})
    print("  DECOY_NPM_TOKEN written to .env")


def reset_packages() -> None:
    """Remove the versions the scenarios publish, directly on the registries (no gateway, no events)."""
    print("Resetting attack versions:")
    pw = password()
    for base, user, package, version in ATTACK_VERSIONS:
        token = verdaccio.ensure_user(base, user, pw)
        removed = verdaccio.unpublish_version(base, token, package, version)
        where = "decoy" if base == NPM_DECOY else "real"
        print(f"  {where}: {package}@{version} {'removed' if removed else 'not present'}")


def seed_all() -> None:
    wait_for_services()
    seed_real_gitea()
    seed_decoy_gitea()
    seed_real_verdaccio()
    seed_decoy_verdaccio()
    print("\nSeeding finished.")


COMMANDS = {"wait": wait_for_services, "all": seed_all, "reset-packages": reset_packages}


def main() -> None:
    if len(sys.argv) != 2 or sys.argv[1] not in COMMANDS:
        sys.exit(__doc__)
    COMMANDS[sys.argv[1]]()


if __name__ == "__main__":
    main()

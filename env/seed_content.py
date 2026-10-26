"""The fake files and repos we plant. Everything here is synthetic.

Bait tokens are read from contracts/baits.json (they are public inside this repo by design).
"""
from __future__ import annotations

import json
from pathlib import Path

BAITS_PATH = Path(__file__).resolve().parent.parent / "contracts" / "baits.json"
GATEWAY_NPM = "http://gateway:8081/"


def bait_token(bait_id: str) -> str:
    baits = json.loads(BAITS_PATH.read_text(encoding="utf-8"))
    for bait in baits:
        if bait["bait_id"] == bait_id:
            return bait["token"]
    raise SystemExit(f"{bait_id} not found in {BAITS_PATH}")


def payments_env_file(git_user: str) -> str:
    """The .env in the REAL repo dev/payments-api. It holds the planted BAIT-SRC-01."""
    return (
        "# payments-api local config (do not commit)\n"
        "APP_ENV=staging\n"
        "PORT=3000\n"
        "DATABASE_URL=postgres://payments:not-a-real-password@db.internal:5432/payments\n"
        "PAYMENT_PROVIDER_KEY=pk_test_000000000000000000000000\n"
        f"GITEA_USER={git_user}\n"
        f"GITEA_TOKEN={bait_token('BAIT-SRC-01')}\n"
        "GITEA_URL=http://gateway:8080\n"
    )


def deploy_runbook() -> str:
    """runbooks/deploy.md in the REAL repo dev/docs. It holds the planted BAIT-DOC-04."""
    return (
        "# Deploy runbook\n"
        "\n"
        "Steps to deploy payments-api to staging.\n"
        "\n"
        "1. Merge to `main` and wait for the CI job to pass.\n"
        "2. Check that the repo is reachable with the deploy token:\n"
        "\n"
        "```bash\n"
        "curl -s \\\n"
        f"  -H \"Authorization: token {bait_token('BAIT-DOC-04')}\" \\\n"
        "  http://gateway:8080/api/v1/repos/dev/payments-api\n"
        "```\n"
        "\n"
        "3. Run `npm run deploy:staging` and watch the logs.\n"
        "4. If something breaks, ask in the platform channel.\n"
    )


def ci_pipeline_npmrc() -> str:
    """The .npmrc in the DECOY repo ops/ci-pipeline. It holds BAIT-CI-02."""
    return (
        f"@kfu:registry={GATEWAY_NPM}\n"
        f"//gateway:8081/:_authToken={bait_token('BAIT-CI-02')}\n"
    )


def release_publish_script() -> str:
    """scripts/publish.sh in the DECOY repo ops/release-tools. It holds BAIT-PUB-03."""
    return (
        "#!/usr/bin/env bash\n"
        "# Publish a release build to the internal registry.\n"
        "set -euo pipefail\n"
        f"export NPM_TOKEN={bait_token('BAIT-PUB-03')}\n"
        "npm config set //gateway:8081/:_authToken \"$NPM_TOKEN\"\n"
        f"npm publish --registry {GATEWAY_NPM}\n"
    )


def readme(title: str, text: str) -> str:
    return f"# {title}\n\n{text}\n"


# Each repo: owner (org), name, description, files {path: text}.
# README.md is created automatically by auto_init, so we overwrite it when we list it.

def real_repos(git_user: str) -> list[dict]:
    return [
        {
            "org": "dev", "name": "payments-api",
            "description": "Payments API for the student portal",
            "files": {
                "README.md": readme("payments-api", "REST API for tuition payments. Run `npm start`."),
                "package.json": json.dumps({"name": "payments-api", "version": "0.3.1", "private": True,
                                            "scripts": {"start": "node src/server.js"}}, indent=2) + "\n",
                "src/server.js": "require('http').createServer((_, res) => res.end('ok')).listen(3000);\n",
                ".env": payments_env_file(git_user),
            },
        },
        {
            "org": "dev", "name": "student-portal",
            "description": "Student portal front end",
            "files": {
                "README.md": readme("student-portal", "Front end for the student portal."),
                "package.json": json.dumps({"name": "student-portal", "version": "1.2.0", "private": True}, indent=2) + "\n",
            },
        },
        {
            "org": "dev", "name": "docs",
            "description": "Team documentation",
            "files": {
                "README.md": readme("docs", "Onboarding notes and runbooks."),
                "runbooks/deploy.md": deploy_runbook(),
            },
        },
    ]


def decoy_repos(git_user: str) -> list[dict]:
    """What an attacker sees after the gateway swaps their bait token for the decoy account."""
    return [
        {
            "org": "ops", "name": "ci-pipeline",
            "description": "Build and test pipeline for the @kfu packages",
            "files": {
                "README.md": readme("ci-pipeline", "Runs the build for @kfu packages. Registry settings are in `.npmrc`."),
                ".npmrc": ci_pipeline_npmrc(),
                "build.sh": "#!/usr/bin/env bash\nset -euo pipefail\nnpm ci\nnpm test\n",
            },
        },
        {
            "org": "ops", "name": "release-tools",
            "description": "Release helpers",
            "files": {
                "README.md": readme("release-tools", "Scripts used when we cut a release."),
                "scripts/publish.sh": release_publish_script(),
            },
        },
        {
            "org": "dev", "name": "payments-api",
            "description": "Payments API for the student portal",
            "files": {
                "README.md": readme("payments-api", "REST API for tuition payments. Run `npm start`."),
                "package.json": json.dumps({"name": "payments-api", "version": "0.3.1", "private": True}, indent=2) + "\n",
                ".env.example": "APP_ENV=staging\nPORT=3000\nDATABASE_URL=\n",
            },
        },
        {
            "org": "dev", "name": "student-portal",
            "description": "Student portal front end",
            "files": {"README.md": readme("student-portal", "Front end for the student portal.")},
        },
    ]


# Packages published into both registries. Zero dependencies on purpose:
# an install then only touches these packages (no extra requests, no uplink).
SEED_PACKAGES = [
    ("@kfu/build-utils", "1.4.2", "Small helpers used by the KFU build scripts"),
    ("@kfu/payments-sdk", "2.1.0", "Client SDK for payments-api"),
]

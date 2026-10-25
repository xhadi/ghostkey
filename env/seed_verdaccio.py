"""Seed one Verdaccio registry: users, tokens and the small @kfu packages.

Publishing uses the real `npm` CLI (this runs inside the node:20 setup container).
"""
from __future__ import annotations

import json
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import quote, urlsplit

from env.http_util import request


def ensure_user(base: str, name: str, password: str) -> str:
    """Register `name` (or log in if it already exists) and return a token for it.

    First try to register. If the user exists, Verdaccio answers 409; then we send the
    same request again with Basic auth, which it treats as a login and answers with a token.
    """
    url = f"{base}/-/user/org.couchdb.user:{name}"
    body = {"_id": f"org.couchdb.user:{name}", "name": name, "password": password,
            "email": f"{name}@kfu.example", "type": "user", "roles": [], "date": "2026-10-25T00:00:00.000Z"}
    status, reply = request("PUT", url, body=body)
    if status == 409:
        status, reply = request("PUT", url, body=body, basic=(name, password))
    if status not in (200, 201) or not isinstance(reply, dict) or "token" not in reply:
        raise SystemExit(f"could not create or log in npm user {name} (HTTP {status}). "
                         "If the password changed, remove the verdaccio volumes and run setup again.")
    return reply["token"]


def whoami(base: str, token: str) -> str | None:
    """Return the username this token belongs to, or None."""
    status, body = request("GET", f"{base}/-/whoami", token_header=f"Bearer {token}")
    if status == 200 and isinstance(body, dict):
        return body.get("username")
    return None


def get_packument(base: str, token: str, package: str) -> dict | None:
    status, body = request("GET", f"{base}/{quote(package, safe='@')}", token_header=f"Bearer {token}")
    return body if status == 200 and isinstance(body, dict) else None


def versions_of(base: str, token: str, package: str) -> list[str]:
    packument = get_packument(base, token, package)
    return sorted(packument.get("versions", {})) if packument else []


def _run_npm(base: str, token: str, args: list[str], cwd: Path | None = None) -> None:
    """Run npm against `base` with a throwaway user config and cache."""
    host = urlsplit(base).netloc
    with tempfile.TemporaryDirectory() as tmp:
        rc = Path(tmp) / "npmrc"
        rc.write_text(f"registry={base}/\n//{host}/:_authToken={token}\n", encoding="utf-8")
        cmd = ["npm", *args, "--registry", f"{base}/", "--userconfig", str(rc), "--cache", str(Path(tmp) / "cache"),
               "--no-update-notifier", "--no-audit", "--no-fund", "--loglevel=warn"]
        result = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if result.returncode != 0:
        raise SystemExit(f"npm {args[0]} failed:\n{result.stderr.strip()}")


def publish_package(base: str, token: str, package: str, version: str, description: str) -> None:
    """Publish a tiny package with zero dependencies. Skips it if the version already exists."""
    if version in versions_of(base, token, package):
        print(f"  {package}@{version}: already there")
        return
    with tempfile.TemporaryDirectory() as tmp:
        folder = Path(tmp)
        manifest = {"name": package, "version": version, "description": description,
                    "main": "index.js", "license": "UNLICENSED"}
        (folder / "package.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
        (folder / "index.js").write_text(f"module.exports = {{ name: {package!r}, version: {version!r} }};\n", encoding="utf-8")
        _run_npm(base, token, ["publish"], cwd=folder)
    print(f"  {package}@{version}: published")


def unpublish_version(base: str, token: str, package: str, version: str) -> bool:
    """Remove one version directly on the registry. Returns True if something was removed."""
    if version not in versions_of(base, token, package):
        return False
    _run_npm(base, token, ["unpublish", f"{package}@{version}", "--force"])
    return True

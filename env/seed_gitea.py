"""Seed one Gitea instance over its HTTP API (users are created by env/setup.sh with the gitea CLI)."""
from __future__ import annotations

import base64

from env.http_util import request


def ensure_token(base: str, user: str, password: str, token_name: str, current: str | None) -> str:
    """Return a working access token for `user`.

    If `current` still works for this user we keep it (so .env does not change on re-runs).
    Otherwise we delete the old token of that name (if any) and create a new one.
    """
    if current:
        status, body = request("GET", f"{base}/api/v1/user", token_header=f"token {current}")
        if status == 200 and isinstance(body, dict) and body.get("login") == user:
            return current
    basic = (user, password)
    request("DELETE", f"{base}/api/v1/users/{user}/tokens/{token_name}", basic=basic)
    status, body = request(
        "POST", f"{base}/api/v1/users/{user}/tokens",
        body={"name": token_name, "scopes": ["all"]}, basic=basic,
    )
    if status != 201 or not isinstance(body, dict) or "sha1" not in body:
        raise SystemExit(f"could not create a token for {user} (HTTP {status}). Was the user created by setup.sh?")
    return body["sha1"]


def ensure_org(base: str, user: str, password: str, org: str) -> None:
    basic = (user, password)
    status, _ = request("GET", f"{base}/api/v1/orgs/{org}", basic=basic)
    if status == 200:
        return
    status, body = request("POST", f"{base}/api/v1/orgs", body={"username": org, "visibility": "private"}, basic=basic)
    if status != 201:
        raise SystemExit(f"could not create org {org} (HTTP {status}): {body}")


def ensure_repo(base: str, user: str, password: str, org: str, name: str, description: str) -> None:
    basic = (user, password)
    status, _ = request("GET", f"{base}/api/v1/repos/{org}/{name}", basic=basic)
    if status == 200:
        return
    status, body = request(
        "POST", f"{base}/api/v1/orgs/{org}/repos",
        body={"name": name, "description": description, "private": True,
              "auto_init": True, "default_branch": "main"},
        basic=basic,
    )
    if status != 201:
        raise SystemExit(f"could not create repo {org}/{name} (HTTP {status}): {body}")


def ensure_file(base: str, user: str, password: str, repo: str, path: str, text: str) -> None:
    """Create the file, or update it if the content differs. `repo` is "owner/name"."""
    basic = (user, password)
    url = f"{base}/api/v1/repos/{repo}/contents/{path}"
    status, existing = request("GET", f"{url}?ref=main", basic=basic)
    payload = {"content": base64.b64encode(text.encode("utf-8")).decode("ascii"),
               "message": f"Add {path}", "branch": "main"}
    if status == 200 and isinstance(existing, dict):
        old = base64.b64decode(existing.get("content", "")).decode("utf-8", errors="replace")
        if old == text:
            return
        payload["sha"] = existing["sha"]
        payload["message"] = f"Update {path}"
        status, body = request("PUT", url, body=payload, basic=basic)
    else:
        status, body = request("POST", url, body=payload, basic=basic)
    if status not in (200, 201):
        raise SystemExit(f"could not write {repo}/{path} (HTTP {status}): {body}")


def seed_repos(base: str, user: str, password: str, repos: list[dict]) -> None:
    for repo in repos:
        ensure_org(base, user, password, repo["org"])
        ensure_repo(base, user, password, repo["org"], repo["name"], repo["description"])
        full = f"{repo['org']}/{repo['name']}"
        for path, text in repo["files"].items():
            ensure_file(base, user, password, full, path, text)
        print(f"  repo {full}: {len(repo['files'])} files")

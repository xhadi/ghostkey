"""Pure gateway logic (no mitmproxy import). Everything here is easy to unit test."""
from __future__ import annotations

import base64
import binascii
import hashlib
import json
import secrets
from urllib.parse import parse_qs, unquote


def token_candidates(authorization: str | None) -> list[str]:
    """Return the strings in an Authorization header that could be a token."""
    if not authorization:
        return []
    parts = authorization.strip().split(None, 1)
    if len(parts) != 2:
        return []
    scheme, value = parts[0].lower(), parts[1].strip()
    if scheme in ("token", "bearer"):
        return [value] if value else []
    if scheme == "basic":
        return _basic_candidates(value)
    return []


def _basic_candidates(encoded: str) -> list[str]:
    """Decode `user:password`. Password first: git sends the token as the password."""
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
    except (binascii.Error, ValueError):  # UnicodeDecodeError is a ValueError
        return []
    if ":" not in decoded:
        return []
    user, password = decoded.split(":", 1)
    return [part for part in (password, user) if part]


def classify_token(candidates: list[str], baits: list[dict], credentials: list[dict]) -> dict:
    """Decide if the request carries a bait, a known real credential, or something else."""
    for candidate in candidates:
        for bait in baits:
            if candidate == bait["token"]:
                return _kind("bait", bait=bait)
    for candidate in candidates:
        digest = hashlib.sha256(candidate.encode("utf-8")).hexdigest()
        for credential in credentials:
            if digest == str(credential.get("sha256", "")).lower():
                return _kind("real", credential_id=credential["credential_id"])
    return _kind("unknown" if candidates else "none")


def _kind(token_kind: str, bait: dict | None = None, credential_id: str | None = None) -> dict:
    return {
        "token_kind": token_kind,
        "bait_id": bait["bait_id"] if bait else None,
        "credential_id": credential_id,
        "bait": bait,
    }


def classify_action(service: str, method: str, path: str) -> tuple[str, str | None]:
    """Return (action, target) for one request. `path` may include a query string."""
    raw_path, _, query = path.partition("?")
    segments = [part for part in unquote(raw_path).split("/") if part]
    if service == "git":
        return _git_action(method, segments, query)
    if service == "npm":
        return _npm_action(method, segments)
    return "other", None


def _git_action(method: str, segments: list[str], query: str) -> tuple[str, str | None]:
    if segments[:2] == ["api", "v1"]:
        return _gitea_api_action(method, segments[2:])
    if len(segments) < 3:
        return "other", None
    repo = f"{segments[0]}/{segments[1].removesuffix('.git')}"
    rest = segments[2:]
    service = parse_qs(query).get("service", [""])[0]
    if method == "GET" and rest == ["info", "refs"]:
        if service == "git-upload-pack":
            return "clone", repo
        if service == "git-receive-pack":
            return "push", repo
    if method == "POST" and rest == ["git-upload-pack"]:
        return "clone", repo
    if method == "POST" and rest == ["git-receive-pack"]:
        return "push", repo
    return "other", None


def _gitea_api_action(method: str, rest: list[str]) -> tuple[str, str | None]:
    """`rest` is the path after /api/v1."""
    if method == "GET" and rest in (["user", "repos"], ["repos", "search"]):
        return "list_repos", None
    target = f"{rest[1]}/{rest[2]}" if rest[:1] == ["repos"] and len(rest) >= 3 else None
    return ("api_read" if method == "GET" else "api_write"), target


def _npm_action(method: str, segments: list[str]) -> tuple[str, str | None]:
    if not segments:
        return "other", None
    if segments[0] == "-":
        if method == "GET" and segments[1:] == ["whoami"]:
            return "login", None
        if method == "GET" and segments[1:] == ["v1", "search"]:
            return "search", None
        return "other", None
    name_length = 2 if segments[0].startswith("@") else 1
    if len(segments) < name_length:
        return "other", None
    package = "/".join(segments[:name_length])
    rest = segments[name_length:]
    if not rest and method == "PUT":
        return "publish", package
    if not rest and method == "GET":
        return "install", package
    is_tarball = len(rest) == 2 and rest[0] == "-" and rest[1].endswith(".tgz")
    if is_tarball and method == "GET":
        return "install", package
    return "other", None


STAGE_BY_ACTION = {
    "list_repos": "source", "clone": "source", "api_read": "source", "api_write": "source",
    "login": "build", "install": "build", "search": "build",
    "push": "publish", "publish": "publish",
}


def stage_for(token_kind: str, bait: dict | None, action: str) -> str:
    """A bait carries its own stage. Everything else is derived from the action."""
    if token_kind == "bait" and bait:
        return bait["stage"]
    return STAGE_BY_ACTION.get(action, "unknown")


def session_id(source_ip: str, bait_id: str | None, credential_id: str | None) -> str:
    """Same client + same token = same session."""
    key = f"{source_ip}|{bait_id or credential_id or 'anon'}"
    return "s_" + hashlib.sha1(key.encode("utf-8")).hexdigest()[:8]


def normalize_ip(peer_ip: str) -> str:
    """Turn `::ffff:1.2.3.4` into `1.2.3.4`. Baselines use plain IPv4."""
    if peer_ip.lower().startswith("::ffff:"):
        return peer_ip[len("::ffff:"):]
    return peer_ip


def result_for(status_code: int | None, action: str, body: bytes | str | None) -> str:
    """ok / denied / error. Verdaccio answers whoami 200 `{}` when the token is not valid."""
    if status_code is None:
        return "error"
    if status_code in (401, 403):
        return "denied"
    if not 200 <= status_code < 400:
        return "error"
    if action == "login" and not _has_username(body):
        return "denied"
    return "ok"


def _has_username(body: bytes | str | None) -> bool:
    try:
        data = json.loads(body or b"")
    except ValueError:  # bad JSON and bad UTF-8 are both ValueError
        return False
    return isinstance(data, dict) and "username" in data


def route_for(token_kind: str, service: str, env: dict) -> dict:
    """Where the request goes. A bait never reaches the real service: no decoy settings = blocked."""
    if token_kind != "bait":
        return {"routed_to": "real"}
    return decoy_route(service, env)


def decoy_route(service: str, env: dict) -> dict:
    """Route to the decoy service with the decoy credential, or `blocked` when it is not configured."""
    settings = {
        "git": ("DECOY_GIT_URL", "DECOY_GIT_TOKEN", "token"),
        "npm": ("DECOY_NPM_URL", "DECOY_NPM_TOKEN", "Bearer"),
    }.get(service)
    if settings is None:
        return {"routed_to": "blocked"}
    url_name, token_name, scheme = settings
    url, token = env.get(url_name), env.get(token_name)
    if not url or not token:
        return {"routed_to": "blocked"}
    return {"routed_to": "decoy", "upstream": url, "authorization": f"{scheme} {token}"}


def containment_route(mode: str | None, service: str, env: dict) -> dict | None:
    """Route override for a contained real credential. None = no containment, route as usual."""
    if mode == "block":
        return {"routed_to": "blocked", "status": 403, "body": b"forbidden"}
    if mode == "divert":
        route = decoy_route(service, env)
        if route["routed_to"] == "blocked":
            return {"routed_to": "blocked", "status": 503, "body": b"blocked"}
        return route
    return None


def new_event_id() -> str:
    return "evt_" + secrets.token_hex(4)


def build_event(
    *,
    ts: str,
    source_ip: str,
    user_agent: str | None,
    service: str,
    method: str,
    path: str,
    token: dict,
    action: str,
    target: str | None,
    routed_to: str,
    status_code: int | None,
    result: str,
    event_id: str | None = None,
) -> dict:
    """Assemble one full events row. `token` is the dict from classify_token."""
    event = {
        "event_id": event_id or new_event_id(),
        "ts": ts,
        "session_id": session_id(source_ip, token["bait_id"], token["credential_id"]),
        "source_ip": source_ip,
        "user_agent": user_agent,
        "token_kind": token["token_kind"],
        "bait_id": token["bait_id"],
        "credential_id": token["credential_id"],
        "stage": stage_for(token["token_kind"], token["bait"], action),
        "service": service,
        "method": method,
        "path": path,
        "action": action,
        "target": target,
        "status_code": status_code,
        "result": result,
        "routed_to": routed_to,
        "incident_id": None,
        "processed": 0,
    }
    return event

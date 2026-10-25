"""Tiny HTTP helper for the seed scripts (standard library only).

It never prints tokens or passwords.
"""
from __future__ import annotations

import base64
import json
import time
import urllib.error
import urllib.request


def request(
    method: str,
    url: str,
    *,
    body: dict | None = None,
    token_header: str | None = None,
    basic: tuple[str, str] | None = None,
) -> tuple[int, object]:
    """Send one request. Returns (status_code, parsed_json_or_text).

    token_header is the full Authorization value, e.g. "token abc" or "Bearer abc".
    basic is (user, password).
    """
    headers = {"Accept": "application/json"}
    data = None
    if body is not None:
        data = json.dumps(body).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if token_header:
        headers["Authorization"] = token_header
    elif basic:
        raw = f"{basic[0]}:{basic[1]}".encode("utf-8")
        headers["Authorization"] = "Basic " + base64.b64encode(raw).decode("ascii")
    req = urllib.request.Request(url, data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            return resp.status, _parse(resp.read())
    except urllib.error.HTTPError as err:
        return err.code, _parse(err.read())


def _parse(raw: bytes) -> object:
    text = raw.decode("utf-8", errors="replace")
    try:
        return json.loads(text)
    except ValueError:
        return text


def wait_until_ready(url: str, label: str, seconds: int = 120) -> None:
    """Poll a URL until it answers 200 (or give up with a clear message)."""
    deadline = time.time() + seconds
    while time.time() < deadline:
        try:
            status, _ = request("GET", url)
            if status == 200:
                print(f"  {label}: ready")
                return
        except OSError:
            pass
        time.sleep(2)
    raise SystemExit(f"{label} did not become ready at {url}. Is the container running?")

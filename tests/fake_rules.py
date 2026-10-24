"""Test-only copy of the CLAUDE.md reference behavior_hits(). The real one lives in brain/rules.py."""
from __future__ import annotations


def fake_behavior_hits(event: dict, baseline: dict | None) -> list[dict]:
    """Return raw hits in the fixed order new_source, out_of_scope, unexpected_publish."""
    if baseline is None:
        return []
    hits: list[dict] = []
    if event["source_ip"] not in baseline["allowed_source_ips"]:
        hits.append({"rule": "new_source", "points": 20})
    target = event["target"]
    if event["action"] not in baseline["allowed_actions"] or (
        target is not None and target not in baseline["allowed_targets"]
    ):
        hits.append({"rule": "out_of_scope", "points": 25})
    if event["action"] in ("publish", "push") and not baseline["may_publish"]:
        hits.append({"rule": "unexpected_publish", "points": 35})
    return hits

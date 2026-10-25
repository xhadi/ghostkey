"""Behavior rules for REAL tokens (pure functions, no DB access).

core/ calls behavior_hits() for every real-token event. The baseline says what the
credential normally does. Anything outside it earns points (see CLAUDE.md "Scoring").
"""
from __future__ import annotations

PUBLISH_ACTIONS = ("publish", "push")

NEW_SOURCE_POINTS = 20
OUT_OF_SCOPE_POINTS = 25
UNEXPECTED_PUBLISH_POINTS = 35


def is_new_source(event: dict, baseline: dict) -> bool:
    """The token is used from an IP address its baseline does not list."""
    return event["source_ip"] not in baseline["allowed_source_ips"]


def is_out_of_scope(event: dict, baseline: dict) -> bool:
    """The action, or the target (when the event has one), is not in the baseline."""
    target = event["target"]
    target_unknown = target is not None and target not in baseline["allowed_targets"]
    return event["action"] not in baseline["allowed_actions"] or target_unknown


def is_unexpected_publish(event: dict, baseline: dict) -> bool:
    """The token publishes or pushes, but its baseline says it never should."""
    return event["action"] in PUBLISH_ACTIONS and not baseline["may_publish"]


def behavior_hits(event: dict, baseline: dict | None) -> list[dict]:
    """Return [{"rule": "new_source", "points": 20}, ...] for one real-token event.

    Order is always new_source, out_of_scope, unexpected_publish.
    Without a baseline we know nothing about the credential, so there are no hits.
    """
    if baseline is None:
        return []
    hits: list[dict] = []
    if is_new_source(event, baseline):
        hits.append({"rule": "new_source", "points": NEW_SOURCE_POINTS})
    if is_out_of_scope(event, baseline):
        hits.append({"rule": "out_of_scope", "points": OUT_OF_SCOPE_POINTS})
    if is_unexpected_publish(event, baseline):
        hits.append({"rule": "unexpected_publish", "points": UNEXPECTED_PUBLISH_POINTS})
    return hits

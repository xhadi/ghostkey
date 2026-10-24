"""Pure scoring helpers for core (no DB access)."""
from __future__ import annotations

STAGE_ORDER = ("source", "build", "publish")
WRITE_ACTIONS = ("push", "publish", "api_write")

BAIT_USE_POINTS = 60
SECOND_STAGE_POINTS = 20
WRITE_OR_PUBLISH_POINTS = 15

# A behavior incident opens when the points of one credential reach this value.
BEHAVIOR_THRESHOLD = 60
# Minutes used for the correlation window and the behavior counting window.
WINDOW_MINUTES = 30


def severity(score: int) -> str:
    """Map a score to a severity label: <40 low, 40-69 medium, 70-89 high, >=90 critical."""
    if score >= 90:
        return "critical"
    if score >= 70:
        return "high"
    if score >= 40:
        return "medium"
    return "low"


def order_stages(stages: list[str]) -> list[str]:
    """Return the distinct known stages ordered source -> build -> publish ('unknown' is dropped)."""
    return [stage for stage in STAGE_ORDER if stage in stages]


def bait_hits(event: dict, incident: dict | None) -> list[dict]:
    """Rule hits for one bait event. `incident` is the incident it joins, or None if it opens one."""
    hits = [{"rule": "bait_use", "points": BAIT_USE_POINTS}]
    stage = event["stage"]
    if incident is not None and stage != "unknown" and stage not in incident["stages"]:
        hits.append({"rule": "second_stage_bait", "points": SECOND_STAGE_POINTS})
    if event["action"] in WRITE_ACTIONS:
        hits.append({"rule": "bait_write_or_publish", "points": WRITE_OR_PUBLISH_POINTS})
    return hits

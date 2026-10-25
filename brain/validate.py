"""Check an analysis body against the contract in CLAUDE.md "Analyst output (brain)".

validate() returns a list of error strings. An empty list means the body is valid.
Nothing here decides anything: a rejected body is simply replaced by the rules-only analysis.
"""
from __future__ import annotations

ALLOWED_LABELS = ("recon_only", "source_theft", "package_publish", "credential_harvest",
                  "automated_secret_scanner", "unknown")
ALLOWED_CONFIDENCE = ("high", "medium", "low")

STRING_KEYS = ("summary", "recommended_action", "limits")


def check_string(body: dict, key: str) -> list[str]:
    if key not in body:
        return [f"{key}: missing"]
    if not isinstance(body[key], str):
        return [f"{key}: must be a string"]
    return []


def check_string_list(body: dict, key: str) -> list[str]:
    if key not in body:
        return [f"{key}: missing"]
    if not isinstance(body[key], list):
        return [f"{key}: must be a list"]
    if not all(isinstance(item, str) for item in body[key]):
        return [f"{key}: every item must be a string"]
    return []


def check_hypothesis(body: dict) -> list[str]:
    if "hypothesis" not in body:
        return ["hypothesis: missing"]
    hypothesis = body["hypothesis"]
    if not isinstance(hypothesis, dict):
        return ["hypothesis: must be an object with label and confidence"]
    errors = []
    if "label" not in hypothesis:
        errors.append("hypothesis.label: missing")
    elif hypothesis["label"] not in ALLOWED_LABELS:
        errors.append(f"hypothesis.label: {hypothesis['label']!r} is not an allowed label")
    if "confidence" not in hypothesis:
        errors.append("hypothesis.confidence: missing")
    elif hypothesis["confidence"] not in ALLOWED_CONFIDENCE:
        errors.append(f"hypothesis.confidence: {hypothesis['confidence']!r} must be high, medium or low")
    return errors


def check_alternative(index: int, alternative) -> list[str]:
    name = f"alternatives[{index}]"
    if not isinstance(alternative, dict):
        return [f"{name}: must be an object with label and why"]
    errors = []
    label = alternative.get("label")
    if not isinstance(label, str) or not label.strip():
        errors.append(f"{name}.label: missing or empty")
    elif label not in ALLOWED_LABELS:
        errors.append(f"{name}.label: {label!r} is not an allowed label")
    why = alternative.get("why")
    if not isinstance(why, str) or not why.strip():
        errors.append(f"{name}.why: missing or empty")
    return errors


def check_alternatives(body: dict) -> list[str]:
    if "alternatives" not in body:
        return ["alternatives: missing"]
    alternatives = body["alternatives"]
    if not isinstance(alternatives, list):
        return ["alternatives: must be a list"]
    if not alternatives:
        return ["alternatives: needs at least one alternative"]
    errors = []
    for index, alternative in enumerate(alternatives):
        errors.extend(check_alternative(index, alternative))
    return errors


def check_evidence(body: dict, incident_event_ids: set[str]) -> list[str]:
    """Evidence must be a non-empty list of string ids that all belong to this incident."""
    errors = check_string_list(body, "evidence_event_ids")
    if errors:
        return errors
    evidence = body["evidence_event_ids"]
    if not evidence:
        return ["evidence_event_ids: needs at least one event id"]
    return [f"evidence_event_ids: {event_id!r} is not an event of this incident"
            for event_id in evidence if event_id not in incident_event_ids]


def validate(body: dict, incident_event_ids: set[str]) -> list[str]:
    """Return a list of error strings ([] = valid). Reports every problem it finds."""
    if not isinstance(body, dict):
        return ["body: must be an object"]
    errors: list[str] = []
    for key in STRING_KEYS:
        errors.extend(check_string(body, key))
    for key in ("observed", "assets_at_risk"):
        errors.extend(check_string_list(body, key))
    errors.extend(check_hypothesis(body))
    errors.extend(check_alternatives(body))
    errors.extend(check_evidence(body, incident_event_ids))
    return errors

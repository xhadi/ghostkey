"""LLM analyst call: send one incident to an OpenAI-compatible chat API and return its JSON answer.

Standard library only. `analyze()` never raises: any problem returns None and the worker
falls back to the rules-only analysis. The worker validates the answer (brain/validate.py).
"""
from __future__ import annotations

import json
import os
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
PROMPT_PATH = ROOT / "brain" / "prompts" / "analyst.md"
EXAMPLE_PATH = ROOT / "contracts" / "analysis.example.json"
BAITS_PATH = ROOT / "contracts" / "baits.json"
EXAMPLE_PLACEHOLDER = "{{EXAMPLE_JSON}}"

TIMEOUT_SECONDS = 60
TEMPERATURE = 0.2
# Thinking models are slow at their default effort (glm-5.3-flash: ~64s; "low": ~13s).
# LLM_REASONING_EFFORT=none leaves the field out, for models that reject it.
DEFAULT_REASONING_EFFORT = "low"

# Only these fields leave our network. Never env vars, never anything from baits.json/credentials.json.
INCIDENT_FIELDS = (
    "incident_id", "created_ts", "updated_ts", "signal_kind", "confidence", "score", "severity", "status",
    "source_ips", "token_ids", "stages", "rules_hit",
)
EVENT_FIELDS = (
    "event_id", "ts", "source_ip", "user_agent", "token_kind", "bait_id", "credential_id", "stage",
    "service", "method", "path", "action", "target", "status_code", "result", "routed_to",
)


def load_config() -> dict | None:
    """Read LLM_BASE_URL, LLM_MODEL and LLM_API_KEY now. None if any is missing or blank."""
    base_url = os.environ.get("LLM_BASE_URL", "").strip().rstrip("/")
    model = os.environ.get("LLM_MODEL", "").strip()
    api_key = os.environ.get("LLM_API_KEY", "").strip()
    if not (base_url and model and api_key):
        return None
    effort = os.environ.get("LLM_REASONING_EFFORT", "").strip() or DEFAULT_REASONING_EFFORT
    return {"base_url": base_url, "model": model, "api_key": api_key, "reasoning_effort": effort}


def load_prompt() -> str:
    """The raw analyst prompt file (still has the example placeholder)."""
    return PROMPT_PATH.read_text(encoding="utf-8")


def build_system_prompt() -> str:
    """The prompt with analysis.example.json filled in, so the example never drifts from the contract."""
    example = json.loads(EXAMPLE_PATH.read_text(encoding="utf-8"))
    example_text = json.dumps(example, ensure_ascii=False, indent=2)
    return load_prompt().replace(EXAMPLE_PLACEHOLDER, example_text)


def pick_fields(row: dict, fields: tuple[str, ...]) -> dict:
    """Copy only the allowed fields that exist in the row."""
    return {name: row[name] for name in fields if name in row}


def bait_tokens() -> dict[str, str]:
    """Map each bait token string to its bait_id. Empty if baits.json can't be read."""
    try:
        baits = json.loads(BAITS_PATH.read_text(encoding="utf-8"))
        return {bait["token"]: bait["bait_id"] for bait in baits if bait.get("token")}
    except (OSError, ValueError, KeyError, TypeError, AttributeError):
        return {}


def redact_bait_tokens(text: str) -> str:
    """Safety net: replace any bait token string found in the outgoing text with its bait_id."""
    for token, bait_id in bait_tokens().items():
        text = text.replace(token, bait_id)
    return text


def build_messages(incident: dict, events: list[dict]) -> list[dict]:
    """System prompt plus one user message: compact JSON of the incident and its events."""
    data = {
        "incident": pick_fields(incident, INCIDENT_FIELDS),
        "events": [pick_fields(event, EVENT_FIELDS) for event in events],
    }
    user_text = redact_bait_tokens(json.dumps(data, ensure_ascii=False, separators=(",", ":")))
    return [
        {"role": "system", "content": build_system_prompt()},
        {"role": "user", "content": user_text},
    ]


def build_url(base_url: str) -> str:
    """Join the base URL and /chat/completions, with or without a trailing slash."""
    return base_url.strip().rstrip("/") + "/chat/completions"


def http_post(url: str, headers: dict, payload: dict, timeout: float) -> object:
    """POST JSON and return the decoded JSON reply. Raises on any network or HTTP error."""
    if not url.lower().startswith(("http://", "https://")):
        raise ValueError("unsupported URL scheme")
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(url, data=body, headers=headers, method="POST")
    with urllib.request.urlopen(request, timeout=timeout) as response:  # scheme checked above
        return json.loads(response.read().decode("utf-8"))


def reply_text(response: object) -> str | None:
    """choices[0].message.content as text, or None if the reply has another shape."""
    if not isinstance(response, dict):
        return None
    choices = response.get("choices")
    if not isinstance(choices, list) or not choices or not isinstance(choices[0], dict):
        return None
    message = choices[0].get("message")
    if not isinstance(message, dict):
        return None
    content = message.get("content")
    return content if isinstance(content, str) else None


def strip_fence(text: str) -> str:
    """Remove a leading ``` or ```json line and a trailing ``` line."""
    text = text.strip()
    if not text.startswith("```"):
        return text
    first_newline = text.find("\n")
    text = text[first_newline + 1:] if first_newline != -1 else ""
    text = text.strip()
    if text.endswith("```"):
        text = text[:-3]
    return text.strip()


def extract_json_object(text: str) -> dict | None:
    """Find a JSON object in model output: plain, fenced, or surrounded by prose.

    Text that is valid JSON but not an object (for example a list) gives None.
    """
    cleaned = strip_fence(text)
    try:
        value = json.loads(cleaned)
    except ValueError:
        return parse_inner_object(cleaned)
    return value if isinstance(value, dict) else None


def parse_inner_object(text: str) -> dict | None:
    """Parse the part from the first { to the last }. None if there is no object there."""
    start, end = text.find("{"), text.rfind("}")
    if start == -1 or end <= start:
        return None
    try:
        value = json.loads(text[start:end + 1])
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def log_failure(error: BaseException) -> None:
    """One short line: exception class (and HTTP status). Never the message, so a key can't leak."""
    detail = type(error).__name__
    status = getattr(error, "code", None)
    if isinstance(status, int):
        detail += f" {status}"
    print(f"brain: llm call failed ({detail})")


def analyze(incident: dict, events: list[dict], post=None) -> dict | None:
    """Ask the LLM about one incident. Returns the analysis dict, or None on ANY problem.

    `post(url, headers, payload, timeout)` is injectable so tests never hit the network.
    """
    config = load_config()
    if config is None:
        return None
    send = post or http_post
    try:
        payload = {
            "model": config["model"],
            "messages": build_messages(incident, events),
            "temperature": TEMPERATURE,
        }
        if config["reasoning_effort"].lower() != "none":
            payload["reasoning_effort"] = config["reasoning_effort"]
        headers = {
            "Authorization": "Bearer " + config["api_key"],
            "Content-Type": "application/json",
        }
        response = send(build_url(config["base_url"]), headers, payload, TIMEOUT_SECONDS)
        text = reply_text(response)
        return extract_json_object(text) if text is not None else None
    except Exception as error:  # analyze() must never raise
        log_failure(error)
        return None

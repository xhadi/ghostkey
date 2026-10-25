"""The rules-only analysis: a deterministic body for contracts/analysis.example.json.

No LLM and no randomness. The same incident and events always give the same body, and the body
always passes brain/validate.py, so the system works fully without an LLM (CLAUDE.md "Analyst output").
Labels and ids stay in English. The text fields are short Arabic templates.
"""
from __future__ import annotations

PUBLISH_ACTIONS = ("publish", "push")
SOURCE_THEFT_ACTIONS = ("clone", "api_write")
WRITE_ACTIONS = ("push", "publish", "api_write")
RECON_ACTIONS = ("list_repos", "api_read", "search", "install", "login")

ASSET_PREFIX = {"git": "git repo", "npm": "internal npm registry"}

# How each action reads inside the summary sentence ("الخطوات بالترتيب: ...").
STEP_TEXT = {
    "list_repos": "استعراض المستودعات",
    "clone": "نسخ مستودع",
    "login": "اختبار صلاحية التوكن",
    "publish": "محاولة نشر حزمة",
    "push": "محاولة رفع تعديلات على مستودع",
    "api_read": "قراءة بيانات عبر الـ API",
    "api_write": "كتابة بيانات عبر الـ API",
    "search": "بحث في السجل",
    "install": "تنزيل حزمة",
}

# The "attempt" noun used when we say a write makes the scanner explanation less likely.
WRITE_NOUN = {
    "publish": "محاولة النشر",
    "push": "محاولة رفع التعديلات",
    "api_write": "محاولة الكتابة",
}

HYPOTHESIS_CONFIDENCE = {"bait": "medium", "behavior": "low"}
DEFAULT_ALTERNATIVE = {"bait": "automated_secret_scanner", "behavior": "unknown"}
FALLBACK_ALTERNATIVES = ("recon_only", "unknown", "automated_secret_scanner")

COMMA = "، "


# ---------------------------------------------------------------- what the events show

def observed_actions(events: list[dict]) -> list[str]:
    """Actions in time order: `other` dropped, then consecutive duplicates collapsed."""
    actions: list[str] = []
    for event in events:
        action = event["action"]
        if action != "other" and (not actions or actions[-1] != action):
            actions.append(action)
    return actions


def choose_label(observed: list[str]) -> str:
    """The hypothesis label. The first matching rule wins."""
    if any(action in PUBLISH_ACTIONS for action in observed):
        return "package_publish"
    if any(action in SOURCE_THEFT_ACTIONS for action in observed):
        return "source_theft"
    if observed and all(action == "login" for action in observed):
        return "credential_harvest"
    if observed and all(action in RECON_ACTIONS for action in observed):
        return "recon_only"
    return "unknown"


# The actions that can decide each label. `unknown` has no deciding action.
DECIDING_ACTIONS = {
    "package_publish": PUBLISH_ACTIONS,
    "source_theft": SOURCE_THEFT_ACTIONS,
    "credential_harvest": ("login",),
    "recon_only": RECON_ACTIONS,
}


def deciding_event(label: str, events: list[dict]) -> dict | None:
    """The first event of the action that decided the label (None for `unknown`)."""
    actions = DECIDING_ACTIONS.get(label, ())
    return next((event for event in events if event["action"] in actions), None)


def evidence_ids(incident: dict, events: list[dict], label: str) -> list[str]:
    """Event ids behind the hypothesis, in time order. Never empty, always inside the incident."""
    wanted = {hit["event_id"] for hit in incident["rules_hit"]}
    decider = deciding_event(label, events)
    if decider is not None:
        wanted.add(decider["event_id"])
    ids = [event["event_id"] for event in events if event["event_id"] in wanted]
    return ids or [events[0]["event_id"]]


def asset_name(event: dict) -> str:
    return f"{ASSET_PREFIX[event['service']]}: {event['target']}"


def assets_at_risk(events: list[dict]) -> list[str]:
    """Distinct targets in time order, like 'internal npm registry: @kfu/build-utils'."""
    names = [asset_name(event) for event in events if event["target"] is not None]
    return list(dict.fromkeys(names))


def targets_of(events: list[dict], actions: tuple[str, ...]) -> list[str]:
    """Distinct targets of the given actions, in time order."""
    found = [e["target"] for e in events if e["action"] in actions and e["target"] is not None]
    return list(dict.fromkeys(found))


# ---------------------------------------------------------------- alternatives

def pick_alternative_label(kind: str, label: str) -> str:
    """The usual alternative for this kind of incident, or another sensible one if it equals the label."""
    alternative = DEFAULT_ALTERNATIVE[kind]
    if alternative != label:
        return alternative
    return next(other for other in FALLBACK_ALTERNATIVES if other != label)


def scanner_why(events: list[dict]) -> str:
    text = "أدوات فحص الأسرار الآلية تجرّب المفاتيح المسربة."
    write = next((e["action"] for e in events if e["action"] in WRITE_ACTIONS), None)
    if write is not None:
        text += f" لكن {WRITE_NOUN[write]} تضعف هالاحتمال."
    return text


def alternative_why(label: str, events: list[dict]) -> str:
    if label == "automated_secret_scanner":
        return scanner_why(events)
    if label == "unknown":
        return ("ممكن يكون مطوّر يشغّل البناء من جهازه بتوكن الـ CI بدون إذن. "
                "السلوك مخالف للخط الأساسي، لكنه مو دليل قاطع على هجوم.")
    return "ممكن يكون استكشاف فقط بدون هدف واضح، والأحداث ما تكفي لمعرفة النية."


def alternatives(incident: dict, label: str, events: list[dict]) -> list[dict]:
    alternative = pick_alternative_label(incident["signal_kind"], label)
    return [{"label": alternative, "why": alternative_why(alternative, events)}]


# ---------------------------------------------------------------- Arabic text

def events_phrase(count: int) -> str:
    """'حدث واحد', 'حدثين', '3 أحداث', ... '11 حدث'."""
    if count == 1:
        return "حدث واحد"
    if count == 2:
        return "حدثين"
    if count <= 10:
        return f"{count} أحداث"
    return f"{count} حدث"


def summary_text(incident: dict, observed: list[str]) -> str:
    tokens = COMMA.join(incident["token_ids"])
    ips = COMMA.join(incident["source_ips"])
    if incident["signal_kind"] == "bait":
        opening = f"جلسة من {ips} استخدمت مفتاح طُعم ({tokens})."
    else:
        opening = f"التوكن الحقيقي {tokens} استُخدم من {ips} بشكل يخالف الخط الأساسي."
    steps = COMMA.join(STEP_TEXT.get(action, action) for action in observed) or "ما فيه خطوات واضحة"
    return f"{opening} الخطوات بالترتيب: {steps}."


def recommended_action_text(incident: dict, events: list[dict]) -> str:
    tokens = COMMA.join(incident["token_ids"])
    if incident["signal_kind"] == "bait":
        sentences = [f"تعطيل الطعوم المكشوفة ({tokens})، والبحث عن مصدر تسريبها."]
    else:
        sentences = [f"مراجعة بشرية قبل إلغاء التوكن {tokens}."]
    for package in targets_of([e for e in events if e["service"] == "npm"], ("publish",)):
        sentences.append(f"التأكد من آخر إصدار منشور للحزمة {package} قبل ما أحد يثبّته.")
    for repo in targets_of([e for e in events if e["service"] == "git"], ("push",)):
        sentences.append(f"مراجعة آخر التعديلات المرفوعة على {repo}.")
    return " ".join(sentences)


def limits_text(incident: dict, event_count: int) -> str:
    basis = (f"الفرضية مبنية على {events_phrase(event_count)}، "
             "والتحليل مبني على قواعد ثابتة بدون نموذج لغوي (LLM).")
    if incident["signal_kind"] == "bait":
        return f"{basis} ما نعرف هوية المهاجم، وما نشوف نشاطه خارج خدماتنا."
    return f"{basis} الحكم يعتمد على خط أساس مكتوب يدويًا، فالثقة منخفضة."


# ---------------------------------------------------------------- main entry point

def rules_analysis(incident: dict, events: list[dict]) -> dict:
    """Build the analysis body. `events` are the incident's events ordered by ts, event_id (not empty)."""
    observed = observed_actions(events)
    label = choose_label(observed)
    return {
        "summary": summary_text(incident, observed),
        "observed": observed,
        "hypothesis": {"label": label, "confidence": HYPOTHESIS_CONFIDENCE[incident["signal_kind"]]},
        "evidence_event_ids": evidence_ids(incident, events, label),
        "alternatives": alternatives(incident, label, events),
        "assets_at_risk": assets_at_risk(events),
        "recommended_action": recommended_action_text(incident, events),
        "limits": limits_text(incident, len(events)),
    }

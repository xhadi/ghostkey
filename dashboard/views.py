"""HTML builders for the dashboard (no streamlit import, so tests can run anywhere).

Rules for this file:
- Every string that comes from the DB goes through esc() before it enters HTML.
  Event fields (path, user_agent, target ...) are written by the attacker.
- Builders return ONE line of HTML (no blank lines), because Streamlit's markdown
  parser ends an HTML block at the first blank line.
"""
from __future__ import annotations

import html
from datetime import datetime, timezone

from common import db

# An event younger than this many seconds gets the "fresh" animation in the stage map.
FRESH_SECONDS = 8

STAGE_ORDER = ("source", "build", "publish")
STAGE_NAMES = {"source": "Source", "build": "Build", "publish": "Publish", "unknown": "Other"}
SEVERITY_NAMES = {"low": "Low", "medium": "Medium", "high": "High", "critical": "Critical"}
STATUS_NAMES = {"open": "Open", "needs_review": "Needs review", "closed": "Closed"}

HYPOTHESIS_NAMES = {
    "package_publish": "Package publish attempt",
    "source_theft": "Source code theft",
    "recon_only": "Reconnaissance only",
    "credential_harvest": "Credential harvesting",
    "automated_secret_scanner": "Automated secret scanner",
    "unknown": "Unclear goal",
}

# Plain-language text for each scoring rule (see "Scoring" in CLAUDE.md).
RULE_TEXT = {
    "bait_use": "A bait key was used",
    "second_stage_bait": "A bait from a new stage joined the incident",
    "bait_write_or_publish": "A bait key was used to write or publish",
    "new_source": "A real credential was used from a new IP",
    "out_of_scope": "Action or target outside the credential's baseline",
    "unexpected_publish": "Publish, but the baseline says no publishing",
}


def esc(value: object) -> str:
    """HTML-escape any value (None becomes an empty string)."""
    return html.escape("" if value is None else str(value), quote=True)


def fmt_time(ts: str) -> str:
    """'2026-10-25T10:00:41Z' -> '10:00:41 UTC'."""
    return f"{ts[11:19]} UTC" if len(ts) >= 19 else ts


def _clock(ts: str) -> str:
    """'2026-10-25T10:00:41Z' -> '10:00:41'."""
    return ts[11:19]


def _seconds_ago(ts: str, now: datetime) -> float:
    return (now - db.parse_iso(ts)).total_seconds()


def incident_headline(incident: dict) -> str:
    """Plain text, e.g. 'Critical bait incident from 172.30.0.66'."""
    severity = SEVERITY_NAMES.get(incident["severity"], incident["severity"])
    ips = ", ".join(incident["source_ips"]) or "an unknown address"
    return f"{severity} {incident['signal_kind']} incident from {ips}"


# ---------------------------------------------------------------- header band

def header_html(counts: dict[str, int], mark_uri: str) -> str:
    """The purple band: brand lockup (mark, divider, name, tagline), live note and the traffic strip."""
    figures = [
        (counts["events"], "events seen"),
        (counts["decoy"], "to decoy"),
        (counts["real"], "to real"),
    ]
    if counts.get("blocked"):
        figures.append((counts["blocked"], "blocked"))
    figures.append((counts["open_incidents"], "open incidents"))
    figures.append((counts["unlinked_signals"], "unlinked signals"))
    strip = "".join(f"<li><b>{int(n)}</b> {esc(label)}</li>" for n, label in figures)
    return (
        '<header class="gk-band">'
        '<div class="gk-band-top">'
        '<div class="gk-lockup">'
        f'<img src="{esc(mark_uri)}" alt="">'
        '<span class="gk-divider"></span>'
        '<span class="gk-name">GHOSTKEY'
        '<span class="gk-tagline" dir="rtl" lang="ar">فخ سلسلة الإمداد</span></span>'
        '</div>'
        '<div class="gk-band-side">'
        '<p class="gk-subtitle">Bait-key incidents across source, build and publish</p>'
        '<p class="gk-live"><span class="gk-live-dot"></span>Live, refreshes every 2s</p>'
        '</div>'
        '</div>'
        f'<ul class="gk-traffic">{strip}</ul>'
        '</header>'
    )


def empty_state_html() -> str:
    return (
        '<section class="gk-empty">'
        '<h1>No incidents yet</h1>'
        '<p>Run a scenario to see one:</p>'
        '<code>docker compose exec attacker bash /work/scenario1.sh</code>'
        '</section>'
    )


# ---------------------------------------------------------------- incident rail

def rail_label(incident: dict, pending: int) -> str:
    """Markdown label for a rail button. Each paragraph becomes one grid cell, placed by theme.py.

    Order: id, score (right of the id), severity and kind, source IP, optional pending tag.
    """
    severity = SEVERITY_NAMES.get(incident["severity"], incident["severity"])
    parts = [
        incident["incident_id"],
        str(incident["score"]),
        f"{severity}, {incident['signal_kind']}",
        ", ".join(incident["source_ips"]) or "unknown address",
    ]
    if pending:
        parts.append("Approval pending")
    return "\n\n".join(parts)


def rail_style_html(incidents: list[dict]) -> str:
    """One CSS rule per incident: the left edge of its rail button takes the severity colour."""
    rules = "".join(
        f".st-key-inc_{esc(i['incident_id'])} button{{--sev:var(--sev-{esc(i['severity'])});}}"
        for i in incidents
    )
    return f"<style>{rules}</style>"


# ---------------------------------------------------------------- incident detail header

def detail_header_html(incident: dict) -> str:
    severity = SEVERITY_NAMES.get(incident["severity"], incident["severity"])
    facts = [
        ("Severity", severity),
        ("Confidence", incident["confidence"]),
        ("Status", STATUS_NAMES.get(incident["status"], incident["status"])),
        ("Tokens", ", ".join(incident["token_ids"]) or "none"),
        ("Opened", fmt_time(incident["created_ts"])),
    ]
    items = "".join(f"<div><dt>{esc(k)}</dt><dd>{esc(v)}</dd></div>" for k, v in facts)
    return (
        f'<section class="gk-detail-head sev-{esc(incident["severity"])}">'
        f'<p class="gk-id">{esc(incident["incident_id"])}</p>'
        f"<h1>{esc(incident_headline(incident))}</h1>"
        f'<dl class="gk-facts">{items}</dl>'
        "</section>"
    )


# ---------------------------------------------------------------- stage map

def _marker_html(number: int, event: dict, hits: list[dict], cited: bool, fresh: bool) -> str:
    """One event as a marker. The plane class comes from routed_to."""
    classes = ["gk-marker", f"gk-marker-{esc(event['routed_to'])}"]
    if fresh:
        classes.append("fresh")
    if cited:
        classes.append("cited")
    who = event["bait_id"] or event["credential_id"] or "no token"
    target = event["target"] or event["service"]
    badges = "".join(f'<li>+{int(h["points"])} {esc(h["rule"])}</li>' for h in hits)
    badge_list = f'<ul class="gk-badges">{badges}</ul>' if badges else ""
    return (
        f'<article class="{" ".join(classes)}" data-event="{esc(event["event_id"])}">'
        f'<p class="gk-marker-head"><span class="gk-n">{number}</span><b>{esc(event["action"])}</b></p>'
        f'<p class="gk-marker-target">{esc(target)}</p>'
        f'<p class="gk-marker-meta"><span>{esc(_clock(event["ts"]))}</span><span>{esc(who)}</span></p>'
        f"{badge_list}"
        "</article>"
    )


def stage_map_html(
    events: list[dict],
    rules_hit: list[dict],
    evidence_ids: list[str],
    now: datetime | None = None,
) -> str:
    """Stage columns, split by the gateway line into a real plane (above) and a decoy plane (below)."""
    now = now or datetime.now(timezone.utc)
    stages = list(STAGE_ORDER)
    if any(e["stage"] == "unknown" for e in events):
        stages.append("unknown")

    hits_by_event: dict[str, list[dict]] = {}
    for hit in rules_hit:
        hits_by_event.setdefault(hit["event_id"], []).append(hit)

    # cells[(plane, stage)] -> marker HTML strings, in time order.
    cells: dict[tuple[str, str], list[str]] = {}
    for number, event in enumerate(events, start=1):
        marker = _marker_html(
            number,
            event,
            hits_by_event.get(event["event_id"], []),
            cited=event["event_id"] in evidence_ids,
            fresh=_seconds_ago(event["ts"], now) <= FRESH_SECONDS,
        )
        cells.setdefault((event["routed_to"], event["stage"]), []).append(marker)

    def plane_cells(plane: str) -> str:
        return "".join(
            f'<div class="gk-cell">{"".join(cells.get((plane, stage), []))}</div>' for stage in stages
        )

    def has_events(plane: str) -> bool:
        return any(p == plane for p, _ in cells)

    def plane_html(plane: str, label: str, empty_note: str) -> str:
        """A plane with its lanes, or a one-line collapsed plane when nothing went through it."""
        if has_events(plane):
            return (
                f'<div class="gk-plane gk-plane-{plane}"><p class="gk-plane-label">{label}</p>'
                f'<div class="gk-row">{plane_cells(plane)}</div></div>'
            )
        return (
            f'<div class="gk-plane gk-plane-{plane} gk-plane-empty">'
            f'<p class="gk-plane-label">{label}</p><p class="gk-plane-note">{empty_note}</p></div>'
        )

    heads = "".join(f'<div class="gk-head"><span>{STAGE_NAMES[s]}</span></div>' for s in stages)
    # Blocked events sit ON the gateway line, so they live inside the gateway element.
    blocked_cells = ""
    if has_events("blocked"):
        blocked_cells = f'<div class="gk-row gk-on-line">{plane_cells("blocked")}</div>'
    return (
        '<section class="gk-section gk-map-panel">'
        "<h2>Stage map</h2>"
        '<div class="gk-map-scroll">'
        f'<div class="gk-map gk-cols-{len(stages)}">'
        f'<div class="gk-heads">{heads}</div>'
        f'{plane_html("real", "Real services", "No traffic reached real services")}'
        f'<div class="gk-gateway"><span>Gateway</span>{blocked_cells}</div>'
        f'{plane_html("decoy", "Decoy, the ghost layer", "No traffic went to the decoy")}'
        "</div></div>"
        '<p class="gk-legend">A ring marks an event the analyst cites as evidence. '
        "A badge shows the score points that event earned.</p>"
        "</section>"
    )


# ---------------------------------------------------------------- score ledger

def score_ledger_html(incident: dict) -> str:
    """Each counted rule with the event that earned it, then the total."""
    rows = "".join(
        "<li>"
        f'<span class="gk-pts">+{int(h["points"])}</span>'
        f'<span class="gk-rule">{esc(RULE_TEXT.get(h["rule"], h["rule"]))}'
        f'<small>{esc(h["rule"])}, {esc(h["event_id"])}</small></span>'
        "</li>"
        for h in incident["rules_hit"]
    )
    severity = SEVERITY_NAMES.get(incident["severity"], incident["severity"])
    return (
        '<section class="gk-panel">'
        "<h2>Score ledger</h2>"
        f'<ol class="gk-ledger">{rows}</ol>'
        '<p class="gk-total">'
        f'<span class="gk-pts">{int(incident["score"])}</span>'
        f'<span class="gk-total-label sev-{esc(incident["severity"])}">{esc(severity)}</span></p>'
        "</section>"
    )


# ---------------------------------------------------------------- analyst panel

def _rtl(text: object, cls: str = "") -> str:
    """Arabic text block: right-to-left (CSS right-aligns it)."""
    return f'<p class="gk-ar {cls}" dir="rtl" lang="ar">{esc(text)}</p>'


def _chips(items: list[str]) -> str:
    chips = "".join(f"<li>{esc(i)}</li>" for i in items)
    return f'<ul class="gk-chips">{chips}</ul>' if chips else '<p class="gk-none">None</p>'


def analyst_html(analysis: dict | None, event_count: int) -> str:
    if analysis is None:
        return (
            '<section class="gk-panel"><h2>Analyst</h2>'
            '<p class="gk-quiet">Analysis pending. The analyst runs within a few seconds of new events.</p>'
            "</section>"
        )
    body = analysis["body"]
    source = "LLM analyst" if analysis["source"] == "llm" else "Rules-only analyst"
    notes = ""
    if not analysis["valid"]:
        notes += '<p class="gk-note">The LLM output failed validation, so the rules-only analysis is shown.</p>'
    if analysis["based_on_event_count"] < event_count:
        notes += '<p class="gk-note">Updating with new events</p>'

    hypothesis = body["hypothesis"]
    label = HYPOTHESIS_NAMES.get(hypothesis["label"], hypothesis["label"])
    alternatives = "".join(
        f'<li><b>{esc(HYPOTHESIS_NAMES.get(a["label"], a["label"]))}</b>{_rtl(a["why"])}</li>'
        for a in body["alternatives"]
    )
    return (
        '<section class="gk-panel">'
        f'<h2>Analyst <span class="gk-source">{esc(source)}</span></h2>'
        f"{notes}"
        f'<p class="gk-hypothesis">{esc(label)}'
        f'<span class="gk-confidence">{esc(hypothesis["confidence"])} confidence</span></p>'
        f'{_rtl(body["summary"], "gk-summary")}'
        '<div class="gk-three">'
        f'<div><h3>Observed</h3>{_chips(body["observed"])}</div>'
        f'<div><h3>Assets at risk</h3>{_chips(body["assets_at_risk"])}</div>'
        f'<div><h3>Evidence events</h3>{_chips(body["evidence_event_ids"])}</div>'
        "</div>"
        f'<h3>Other explanations</h3><ul class="gk-alts">{alternatives}</ul>'
        f'<h3>Recommended action</h3>{_rtl(body["recommended_action"])}'
        f'<h3>Limits</h3>{_rtl(body["limits"])}'
        "</section>"
    )


# ---------------------------------------------------------------- response panel

ACTION_DONE_TEXT = {
    "notify": "Notified {target}",
    "disable_bait": "Disabled bait {target}",
    "revoke_credential": "Revoked credential {target}",
    "block_publish": "Blocked publish for {target}",
}
ACTION_ASK_TEXT = {
    "revoke_credential": "Revoke credential {target}",
    "block_publish": "Block publish for {target}",
}


def action_sentence(action: dict, pending: bool = False) -> str:
    """Plain sentence for an action. pending=True gives the imperative form used on the approval card."""
    table = ACTION_ASK_TEXT if pending else ACTION_DONE_TEXT
    template = table.get(action["kind"], action["kind"] + " {target}")
    return template.format(target=action["target"] or "")


def pending_action_html(action: dict) -> str:
    """The sentence above the Approve / Reject buttons (the buttons are streamlit widgets)."""
    return f'<p class="gk-ask">{esc(action_sentence(action, pending=True))}</p>'


def approval_note_html() -> str:
    return '<p class="gk-quiet">Approving records the decision. Ghostkey never changes external systems.</p>'


def decided_action_html(action: dict) -> str:
    verb = "Approved" if action["status"] == "approved" else "Rejected"
    when = fmt_time(action["decided_ts"]) if action["decided_ts"] else ""
    return (
        '<li class="gk-decided">'
        f"<span>{esc(action_sentence(action, pending=True))}</span>"
        f'<small>{verb} by {esc(action["decided_by"])} at {esc(when)}</small></li>'
    )


def auto_log_html(actions: list[dict]) -> str:
    """Quiet log of automatic actions plus any decided approvals."""
    lines = [
        f'<li><span>{esc(action_sentence(a))}</span><small>{esc(fmt_time(a["ts"]))}</small></li>'
        for a in actions
        if a["tier"] == "auto" and a["status"] == "done"
    ]
    lines += [
        decided_action_html(a)
        for a in actions
        if a["tier"] == "approval" and a["status"] in ("approved", "rejected")
    ]
    if not lines:
        return ""
    return f'<h3>Done</h3><ul class="gk-log">{"".join(lines)}</ul>'


# ---------------------------------------------------------------- event log

EVENT_LOG_HEADINGS = (
    "#", "Time", "Source IP", "Token", "Stage", "Action", "Target",
    "Result", "Routed", "Method", "Path", "User agent",
)


def event_log_html(events: list[dict]) -> str:
    """Full table of the incident's events. The raw path is the only monospace text."""
    header = "".join(f"<th>{esc(h)}</th>" for h in EVENT_LOG_HEADINGS)
    rows = ""
    for number, e in enumerate(events, start=1):
        cells = [
            number,
            _clock(e["ts"]),
            e["source_ip"],
            e["bait_id"] or e["credential_id"] or "",
            e["stage"],
            e["action"],
            e["target"],
            f'{e["result"] or ""} {e["status_code"] or ""}'.strip(),
            e["routed_to"],
            e["method"],
        ]
        tds = "".join(f"<td>{esc(c)}</td>" for c in cells)
        tds += f'<td class="gk-path">{esc(e["path"])}</td><td>{esc(e["user_agent"])}</td>'
        rows += f"<tr>{tds}</tr>"
    return (
        '<div class="gk-table-scroll"><table class="gk-table">'
        f"<thead><tr>{header}</tr></thead><tbody>{rows}</tbody></table></div>"
    )

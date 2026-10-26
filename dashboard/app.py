"""Ghostkey dashboard (Streamlit entry point).

Run from the repo root:  streamlit run dashboard/app.py
Read-only, except the Block / Divert / Reject / Approve buttons (see queries.decide_action).
"""
from __future__ import annotations

import sys
from pathlib import Path

# `streamlit run dashboard/app.py` puts dashboard/ on sys.path, not the repo root.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import streamlit as st  # noqa: E402

from common import db  # noqa: E402
from dashboard import queries, theme, views  # noqa: E402

DEFAULT_REVIEWER = "analyst"

# Static labels: changing a radio's labels would reset its state.
VIEW_INCIDENTS = "Incidents"
VIEW_TRAFFIC = "All traffic"
VIEWS = (VIEW_INCIDENTS, VIEW_TRAFFIC)
VIEW_PARAMS = {"incidents": VIEW_INCIDENTS, "traffic": VIEW_TRAFFIC}

ROUTED_OPTIONS = ("real", "decoy", "blocked")
TOKEN_KIND_OPTIONS = ("bait", "real", "unknown", "none")
SERVICE_OPTIONS = ("git", "npm")
STAGE_OPTIONS = ("source", "build", "publish", "unknown")
FILTER_KEYS = ("f_routed", "f_kind", "f_service", "f_stage", "f_linked", "f_search")


def keep_filters() -> None:
    """Streamlit drops the state of widgets that are not drawn, so the filters would reset while
    the Incidents view is open. Writing each value back to itself keeps it."""
    for key in FILTER_KEYS:
        if key in st.session_state:
            st.session_state[key] = st.session_state[key]


def pick_incident(incident_id: str) -> None:
    """Button callback: the user chose an incident, so stop auto-following the newest."""
    st.session_state["picked"] = incident_id


def decide(action_id: int, decision: str) -> None:
    """Button callback: record the reviewer's decision."""
    reviewer = st.session_state.get("reviewer", DEFAULT_REVIEWER)
    conn = queries.open_db()
    try:
        queries.decide_action(conn, action_id, decision, reviewer)
    finally:
        conn.close()


def apply_view_param() -> None:
    """On the first run, ?view=traffic opens the All traffic tab (handy for screenshots)."""
    if st.session_state.get("view_param_applied"):
        return
    st.session_state["view_param_applied"] = True
    wanted = VIEW_PARAMS.get(st.query_params.get("view", ""))
    if wanted:
        st.session_state["view"] = wanted


def apply_query_param(incidents: list[dict]) -> None:
    """On the first run, ?incident=INC-002 preselects that incident (handy for screenshots)."""
    if st.session_state.get("query_param_applied"):
        return
    st.session_state["query_param_applied"] = True
    wanted = st.query_params.get("incident")
    if wanted and any(i["incident_id"] == wanted for i in incidents):
        st.session_state["picked"] = wanted


def selected_incident(incidents: list[dict]) -> dict:
    """The user's pick if it still exists, otherwise the newest incident."""
    picked = st.session_state.get("picked")
    for incident in incidents:
        if incident["incident_id"] == picked:
            return incident
    return incidents[0]


def render_rail(incidents: list[dict], selected_id: str, pending: dict[str, int]) -> None:
    st.markdown(views.rail_style_html(incidents), unsafe_allow_html=True)
    for incident in incidents:
        incident_id = incident["incident_id"]
        st.button(
            views.rail_label(incident, pending.get(incident_id, 0)),
            key=f"inc_{incident_id}",
            type="primary" if incident_id == selected_id else "secondary",
            on_click=pick_incident,
            args=(incident_id,),
            use_container_width=True,
        )


def render_decision_buttons(action: dict) -> None:
    """The buttons for one pending action, inside one keyed container (theme.py lays them in a row)."""
    action_id = action["action_id"]
    with st.container(key=f"decide_{action_id}"):
        if action["kind"] == "revoke_credential":
            unscoped = not action.get("scope_ip")
            st.button("Block", key=f"block_{action_id}", type="primary", disabled=unscoped,
                      on_click=decide, args=(action_id, "block"))
            st.button("Divert to decoy", key=f"divert_{action_id}", disabled=unscoped,
                      on_click=decide, args=(action_id, "divert"))
        else:
            st.button("Approve", key=f"approve_{action_id}", type="primary",
                      on_click=decide, args=(action_id, "approve"))
        st.button("Reject", key=f"reject_{action_id}",
                  on_click=decide, args=(action_id, "reject"))


def render_response(conn, actions: list[dict]) -> None:
    st.markdown('<section class="gk-section"><h2>Response</h2></section>', unsafe_allow_html=True)
    pending = [a for a in actions if a["tier"] == "approval" and a["status"] == "pending"]
    if pending:
        st.text_input("Reviewer", value=DEFAULT_REVIEWER, key="reviewer")
    for action in pending:
        st.markdown(views.pending_action_html(action), unsafe_allow_html=True)
        render_decision_buttons(action)
        if action["kind"] == "revoke_credential":
            st.markdown(views.approval_note_html(scoped=bool(action.get("scope_ip"))), unsafe_allow_html=True)
        else:
            st.markdown(views.approve_note_html(), unsafe_allow_html=True)
    effects = {
        a["action_id"]: queries.containment_effect(conn, a)
        for a in actions
        if a["kind"] == "revoke_credential" and a["status"] == "approved"
    }
    st.markdown(views.auto_log_html(actions, effects), unsafe_allow_html=True)


def render_detail(conn, incident: dict, contracts: dict, sessions: list[dict]) -> None:
    """One incident page. contracts = {'baselines': ..., 'credentials': ...}, loaded once per run of live()."""
    incident_id = incident["incident_id"]
    events = queries.list_events(conn, incident_id)
    analysis = queries.get_analysis(conn, incident_id)
    actions = queries.list_actions(conn, incident_id)
    evidence = analysis["body"].get("evidence_event_ids", []) if analysis else []

    st.markdown(views.detail_header_html(incident), unsafe_allow_html=True)
    st.markdown(views.reached_real_html(events), unsafe_allow_html=True)
    st.markdown(views.stage_map_html(events, incident["rules_hit"], evidence), unsafe_allow_html=True)
    for panel in (
        views.baseline_html(incident, events, contracts["baselines"], contracts["credentials"]),
        views.elsewhere_html(incident, sessions),
    ):
        if panel:
            st.markdown(panel, unsafe_allow_html=True)
    st.markdown(views.score_ledger_html(incident), unsafe_allow_html=True)
    st.markdown(views.analyst_html(analysis, len(events)), unsafe_allow_html=True)
    render_response(conn, actions)
    with st.expander("Event log", expanded=False):
        st.markdown(views.event_log_html(events), unsafe_allow_html=True)


def render_incidents(conn, contracts: dict) -> None:
    """The Incidents view: the rail on the left, the selected incident on the right."""
    incidents = queries.list_incidents(conn)
    if not incidents:
        st.markdown(views.empty_state_html(), unsafe_allow_html=True)
        return
    apply_query_param(incidents)
    selected = selected_incident(incidents)
    sessions = queries.list_sessions(conn)
    with st.container(key="main"):
        rail_col, detail_col = st.columns([1, 3.2])
        with rail_col:
            render_rail(incidents, selected["incident_id"], queries.pending_approval_counts(conn))
        with detail_col:
            render_detail(conn, selected, contracts, sessions)


def render_filters() -> dict:
    """The filter row above the all-events table. Returns the filters dict for queries.filter_events."""
    with st.container(key="filters"):
        cols = st.columns([1, 1, 1, 1, 1.2, 2])
        return {
            "routed_to": cols[0].multiselect("Routed to", ROUTED_OPTIONS, key="f_routed"),
            "token_kind": cols[1].multiselect("Token kind", TOKEN_KIND_OPTIONS, key="f_kind"),
            "service": cols[2].multiselect("Service", SERVICE_OPTIONS, key="f_service"),
            "stage": cols[3].multiselect("Stage", STAGE_OPTIONS, key="f_stage"),
            "linked": cols[4].selectbox("Linked", queries.LINKED_OPTIONS, key="f_linked"),
            "search": cols[5].text_input("Search", key="f_search", placeholder="IP, token, target, path, agent, incident"),
        }


def render_traffic(conn, total_events: int) -> None:
    """The All traffic view: funnel, activity, sessions, then every event with filters."""
    with st.container(key="traffic"):
        funnel = queries.triage_funnel(conn)
        if funnel["requests"] == 0:
            st.markdown(views.no_traffic_html(), unsafe_allow_html=True)
            return
        events = queries.list_all_events(conn)
        st.markdown(views.funnel_html(funnel), unsafe_allow_html=True)
        st.markdown(views.activity_html(events), unsafe_allow_html=True)
        st.markdown(views.sessions_html(queries.list_sessions(conn)), unsafe_allow_html=True)
        st.markdown('<section class="gk-section gk-filters-head"><h2>Filter events</h2></section>', unsafe_allow_html=True)
        filters = render_filters()
        matched = queries.filter_events(events, filters)
        st.markdown(
            views.all_events_html(matched, total_events, fetched=len(events)),
            unsafe_allow_html=True,
        )


@st.fragment(run_every=2)
def live() -> None:
    """The part of the page that refreshes every 2 seconds. Only the chosen view is queried and drawn."""
    contracts = {"baselines": db.load_json("baselines.json"), "credentials": db.load_json("credentials.json")}
    conn = queries.open_db()
    try:
        counts = queries.traffic_counts(conn)
        st.markdown(views.header_html(counts, theme.mark_data_uri()), unsafe_allow_html=True)
        apply_view_param()
        keep_filters()
        view = st.radio("View", VIEWS, horizontal=True, key="view", label_visibility="collapsed")
        if view == VIEW_TRAFFIC:
            render_traffic(conn, counts["events"])
        else:
            render_incidents(conn, contracts)
    finally:
        conn.close()


st.set_page_config(layout="wide", page_title="Ghostkey", page_icon=str(theme.FAVICON_PATH))
st.markdown(theme.css(), unsafe_allow_html=True)  # once, outside the refreshing fragment
live()

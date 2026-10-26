"""Tests for dashboard/queries.py and dashboard/views.py (neither imports streamlit)."""
from __future__ import annotations

import json
import re
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

from common import db
from dashboard import queries, views
from fixtures.load_fixtures import FIXTURES_DIR, read_events, write_fake_core


def count_fixture_events(*names: str) -> list[dict]:
    return read_events(list(names))


class DashboardTestCase(unittest.TestCase):
    """Base class: a temp DB loaded with the three fixtures plus the fake core state."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        self.conn = db.connect(Path(tmp.name) / "test.db")
        self.addCleanup(self.conn.close)
        db.init(self.conn)
        self.events = read_events(["normal", "scenario1", "scenario2"])
        for event in self.events:
            db.insert_event(self.conn, event)
        write_fake_core(self.conn, self.events)
        self.conn.commit()
        self.state = json.loads((FIXTURES_DIR / "expected_state.json").read_text(encoding="utf-8"))


class QueriesTests(DashboardTestCase):
    def test_incidents_newest_updated_first_with_json_decoded(self) -> None:
        incidents = queries.list_incidents(self.conn)
        # Scenario 2 events are newer than scenario 1 events in the fixtures.
        self.assertEqual([i["incident_id"] for i in incidents], ["INC-002", "INC-001"])
        inc1 = incidents[1]
        expected = self.state["incidents"][0]
        self.assertEqual(inc1["source_ips"], expected["source_ips"])
        self.assertEqual(inc1["token_ids"], expected["token_ids"])
        self.assertEqual(inc1["stages"], expected["stages"])
        self.assertEqual(inc1["rules_hit"], expected["rules_hit"])
        self.assertIsInstance(inc1["rules_hit"][0], dict)

    def test_events_for_incident_are_in_time_order(self) -> None:
        events = queries.list_events(self.conn, "INC-001")
        self.assertEqual([e["event_id"] for e in events], self.state["incidents"][0]["events"])
        stamps = [e["ts"] for e in events]
        self.assertEqual(stamps, sorted(stamps))

    def test_events_of_other_incidents_and_unlinked_events_are_left_out(self) -> None:
        ids = {e["event_id"] for e in queries.list_events(self.conn, "INC-002")}
        self.assertEqual(ids, set(self.state["incidents"][1]["events"]))
        self.assertEqual(queries.list_events(self.conn, "INC-999"), [])

    def test_analysis_body_is_decoded(self) -> None:
        analysis = queries.get_analysis(self.conn, "INC-001")
        self.assertEqual(analysis["source"], "llm")
        self.assertEqual(analysis["body"]["hypothesis"]["label"], "package_publish")
        self.assertTrue(analysis["body"]["summary"])
        self.assertIsNone(queries.get_analysis(self.conn, "INC-999"))

    def test_traffic_counts_match_the_fixture_files(self) -> None:
        events = count_fixture_events("normal", "scenario1", "scenario2")
        counts = queries.traffic_counts(self.conn)
        self.assertEqual(counts["events"], len(events))
        self.assertEqual(counts["decoy"], sum(e["routed_to"] == "decoy" for e in events))
        self.assertEqual(counts["real"], sum(e["routed_to"] == "real" for e in events))
        self.assertEqual(counts["blocked"], sum(e["routed_to"] == "blocked" for e in events))
        self.assertEqual(counts["open_incidents"], len(self.state["incidents"]))
        self.assertEqual(counts["unlinked_signals"], 0)

    def test_unlinked_signals_are_counted(self) -> None:
        self.conn.execute(
            "INSERT INTO signals (ts, event_id, token_id, rule, points, incident_id) VALUES (?,?,?,?,?,NULL)",
            (db.now_iso(), "evt_n0000002", "REAL-CI-01", "new_source", 20),
        )
        self.conn.commit()
        self.assertEqual(queries.traffic_counts(self.conn)["unlinked_signals"], 1)

    def test_pending_approval_counts(self) -> None:
        self.assertEqual(queries.pending_approval_counts(self.conn), {"INC-002": 1})


class DecideActionTests(DashboardTestCase):
    def action_id(self, incident_id: str, kind: str) -> int:
        row = self.conn.execute(
            "SELECT action_id FROM actions WHERE incident_id = ? AND kind = ?", (incident_id, kind)
        ).fetchone()
        return row["action_id"]

    def action_row(self, action_id: int) -> dict:
        return dict(self.conn.execute("SELECT * FROM actions WHERE action_id = ?", (action_id,)).fetchone())

    def test_block_pending_revoke_sets_approved_and_mode(self) -> None:
        action_id = self.action_id("INC-002", "revoke_credential")
        self.assertTrue(queries.decide_action(self.conn, action_id, "block", "hadi"))
        row = self.action_row(action_id)
        self.assertEqual(row["status"], "approved")
        self.assertEqual(row["mode"], "block")
        self.assertEqual(row["decided_by"], "hadi")
        self.assertTrue(row["decided_ts"].endswith("Z"))

    def test_divert_pending_revoke_sets_approved_and_mode(self) -> None:
        action_id = self.action_id("INC-002", "revoke_credential")
        self.assertTrue(queries.decide_action(self.conn, action_id, "divert", "hadi"))
        row = self.action_row(action_id)
        self.assertEqual((row["status"], row["mode"]), ("approved", "divert"))

    def test_reject_pending_action(self) -> None:
        action_id = self.action_id("INC-002", "revoke_credential")
        self.assertTrue(queries.decide_action(self.conn, action_id, "reject", "ghalia"))
        row = self.action_row(action_id)
        self.assertEqual(row["status"], "rejected")
        self.assertIsNone(row["mode"])

    def test_divert_on_revoke_without_scope_ip_changes_nothing(self) -> None:
        action_id = self.action_id("INC-002", "revoke_credential")
        self.conn.execute("UPDATE actions SET scope_ip = NULL WHERE action_id = ?", (action_id,))
        self.conn.commit()
        before = self.action_row(action_id)
        self.assertFalse(queries.decide_action(self.conn, action_id, "divert", "hadi"))
        self.assertFalse(queries.decide_action(self.conn, action_id, "block", "hadi"))
        self.assertEqual(self.action_row(action_id), before)

    def test_approve_on_revoke_changes_nothing(self) -> None:
        action_id = self.action_id("INC-002", "revoke_credential")
        before = self.action_row(action_id)
        self.assertFalse(queries.decide_action(self.conn, action_id, "approve", "hadi"))
        self.assertEqual(self.action_row(action_id), before)

    def test_block_on_non_revoke_action_changes_nothing(self) -> None:
        action_id = self.action_id("INC-002", "notify")
        self.conn.execute("UPDATE actions SET tier = 'approval', status = 'pending' WHERE action_id = ?", (action_id,))
        self.conn.commit()
        before = self.action_row(action_id)
        self.assertFalse(queries.decide_action(self.conn, action_id, "block", "hadi"))
        self.assertEqual(self.action_row(action_id), before)
        self.assertTrue(queries.decide_action(self.conn, action_id, "approve", "hadi"))

    def test_decided_action_cannot_be_decided_again(self) -> None:
        action_id = self.action_id("INC-002", "revoke_credential")
        queries.decide_action(self.conn, action_id, "block", "hadi")
        before = self.action_row(action_id)
        self.assertFalse(queries.decide_action(self.conn, action_id, "reject", "someone-else"))
        self.assertFalse(queries.decide_action(self.conn, action_id, "divert", "someone-else"))
        self.assertEqual(self.action_row(action_id), before)

    def test_auto_action_cannot_be_decided(self) -> None:
        action_id = self.action_id("INC-002", "notify")
        before = self.action_row(action_id)
        self.assertFalse(queries.decide_action(self.conn, action_id, "approve", "hadi"))
        self.assertEqual(self.action_row(action_id), before)

    def test_unknown_action_id_changes_nothing(self) -> None:
        self.assertFalse(queries.decide_action(self.conn, 99999, "approve", "hadi"))

    def test_blank_reviewer_falls_back_to_analyst(self) -> None:
        action_id = self.action_id("INC-002", "revoke_credential")
        queries.decide_action(self.conn, action_id, "block", "   ")
        self.assertEqual(self.action_row(action_id)["decided_by"], "analyst")

    def test_bad_decision_word_is_an_error(self) -> None:
        with self.assertRaises(ValueError):
            queries.decide_action(self.conn, 1, "nuke", "hadi")


def marker_classes(map_html: str) -> dict[str, str]:
    """event_id -> the class attribute of its marker."""
    return {m.group(2): m.group(1) for m in re.finditer(r'<article class="([^"]+)" data-event="([^"]+)"', map_html)}


class ContainmentEffectTests(DashboardTestCase):
    def revoke(self) -> dict:
        return [a for a in queries.list_actions(self.conn, "INC-002") if a["kind"] == "revoke_credential"][0]

    def add_event(self, event_id: str, ts: str, source_ip: str, routed_to: str, credential_id: str = "REAL-CI-01") -> None:
        event = dict(self.events[0], event_id=event_id, ts=ts, source_ip=source_ip, routed_to=routed_to,
                     credential_id=credential_id, incident_id=None, processed=1)
        db.insert_event(self.conn, event)
        self.conn.commit()

    def decide(self, mode: str) -> dict:
        action_id = self.revoke()["action_id"]
        self.conn.execute(
            "UPDATE actions SET status='approved', mode=?, decided_by='hadi', decided_ts=? WHERE action_id=?",
            (mode, "2026-10-25T12:00:00Z", action_id),
        )
        self.conn.commit()
        return self.revoke()

    def test_block_counts_only_matching_credential_ip_route_and_time(self) -> None:
        action = self.decide("block")
        self.add_event("evt_c0000001", "2026-10-25T11:59:59Z", "172.30.0.77", "blocked")  # before the decision
        self.add_event("evt_c0000002", "2026-10-25T12:00:05Z", "172.30.0.77", "blocked")  # counts
        self.add_event("evt_c0000003", "2026-10-25T12:00:06Z", "172.30.0.77", "blocked")  # counts
        self.add_event("evt_c0000004", "2026-10-25T12:00:07Z", "172.30.0.88", "blocked")  # other IP
        self.add_event("evt_c0000005", "2026-10-25T12:00:08Z", "172.30.0.77", "blocked", "REAL-OTHER")  # other credential
        self.add_event("evt_c0000006", "2026-10-25T12:00:09Z", "172.30.0.77", "decoy")  # wrong route for block
        self.assertEqual(queries.containment_effect(self.conn, action), 2)

    def test_divert_counts_decoy_routed_events(self) -> None:
        action = self.decide("divert")
        self.add_event("evt_c0000007", "2026-10-25T12:00:05Z", "172.30.0.77", "decoy")
        self.add_event("evt_c0000008", "2026-10-25T12:00:06Z", "172.30.0.77", "blocked")
        self.assertEqual(queries.containment_effect(self.conn, action), 1)

    def test_zero_when_not_an_approved_revoke(self) -> None:
        self.assertEqual(queries.containment_effect(self.conn, self.revoke()), 0)
        notify = [a for a in queries.list_actions(self.conn, "INC-002") if a["kind"] == "notify"][0]
        self.assertEqual(queries.containment_effect(self.conn, notify), 0)
        rejected = dict(self.decide("block"), status="rejected")
        self.assertEqual(queries.containment_effect(self.conn, rejected), 0)


class DecidedLineTests(DashboardTestCase):
    def action(self, **changes) -> dict:
        base = {"kind": "revoke_credential", "target": "REAL-CI-01", "scope_ip": "172.30.0.77", "tier": "approval",
                "status": "approved", "mode": "block", "decided_by": "hadi", "decided_ts": "2026-10-25T15:44:10Z",
                "ts": "2026-10-25T15:40:00Z"}
        base.update(changes)
        return base

    def test_blocked_line(self) -> None:
        line = views.decided_action_html(self.action(), 3)
        self.assertIn("Blocked at our gateway: REAL-CI-01 from 172.30.0.77 · 3 requests stopped since 15:44:10 UTC", line)

    def test_diverted_line(self) -> None:
        line = views.decided_action_html(self.action(mode="divert"), 2)
        self.assertIn("Diverted to decoy: REAL-CI-01 from 172.30.0.77 · 2 requests diverted since 15:44:10 UTC", line)

    def test_rejected_line(self) -> None:
        line = views.decided_action_html(self.action(status="rejected", mode=None))
        self.assertIn("Rejected by hadi at 15:44:10 UTC, nothing changed", line)

    def test_approved_revoke_without_mode_does_not_claim_enforcement(self) -> None:
        line = views.decided_action_html(self.action(mode=None))
        self.assertNotIn("Blocked", line)
        self.assertNotIn("Diverted", line)
        self.assertIn("not enforced", line)

    def test_pending_sentence_and_notes(self) -> None:
        pending = self.action(status="pending", mode=None, decided_by=None, decided_ts=None)
        self.assertIn("Stop REAL-CI-01 from 172.30.0.77 at our gateway", views.pending_action_html(pending))
        self.assertIn("Applies only to this credential from this IP. Rotating the credential is still up to "
                      "its owner. Ghostkey never changes external systems.", views.approval_note_html())
        self.assertIn("No IP scope on this action; cannot be enforced", views.approval_note_html(scoped=False))

    def test_non_revoke_action_keeps_approved_line(self) -> None:
        action = self.action(kind="block_publish", target="@kfu/x", scope_ip=None, mode=None)
        self.assertIn("Approved by hadi at 15:44:10 UTC", views.decided_action_html(action))

    def test_auto_log_uses_effects_and_never_says_revoked(self) -> None:
        actions = queries.list_actions(self.conn, "INC-002")
        revoke = [a for a in actions if a["kind"] == "revoke_credential"][0]
        decided = dict(revoke, status="approved", mode="block", decided_by="hadi", decided_ts="2026-10-25T15:44:10Z")
        others = [a for a in actions if a is not revoke]
        log = views.auto_log_html(others + [decided], {decided["action_id"]: 4})
        self.assertIn("4 requests stopped", log)
        self.assertNotIn("Revoked credential", log)
        self.assertNotIn("Revoked credential", views.auto_log_html(actions))
        self.assertNotIn("Revoked credential", views.auto_log_html([dict(decided, status="rejected", mode=None)]))

    def test_decided_line_escapes_target_and_ip(self) -> None:
        evil = "<script>alert(1)</script>"
        line = views.decided_action_html(self.action(target=evil, scope_ip=evil, decided_by=evil), 1)
        self.assertNotIn("<script>", line)
        self.assertIn("&lt;script&gt;", line)
        self.assertNotIn("\n", line)


class StageMapTests(DashboardTestCase):
    def build_map(self, incident_id: str, now: datetime | None = None) -> str:
        incident = next(i for i in queries.list_incidents(self.conn) if i["incident_id"] == incident_id)
        events = queries.list_events(self.conn, incident_id)
        analysis = queries.get_analysis(self.conn, incident_id)
        return views.stage_map_html(
            events, incident["rules_hit"], analysis["body"]["evidence_event_ids"], now=now
        )

    def test_decoy_events_sit_below_the_gateway(self) -> None:
        map_html = self.build_map("INC-001")
        gateway_at = map_html.index('class="gk-gateway"')
        for event_id, classes in marker_classes(map_html).items():
            self.assertIn("gk-marker-decoy", classes)
            self.assertGreater(map_html.index(f'data-event="{event_id}"'), gateway_at)
        self.assertEqual(len(marker_classes(map_html)), 5)

    def test_real_events_sit_above_the_gateway(self) -> None:
        map_html = self.build_map("INC-002")
        gateway_at = map_html.index('class="gk-gateway"')
        for event_id, classes in marker_classes(map_html).items():
            self.assertIn("gk-marker-real", classes)
            self.assertLess(map_html.index(f'data-event="{event_id}"'), gateway_at)
        self.assertEqual(len(marker_classes(map_html)), 3)

    def test_rule_badges_and_evidence_rings(self) -> None:
        map_html = self.build_map("INC-001")
        self.assertIn("+60 bait_use", map_html)
        self.assertIn("+20 second_stage_bait", map_html)
        self.assertIn("+15 bait_write_or_publish", map_html)
        classes = marker_classes(map_html)
        self.assertIn("cited", classes["evt_s1000001"])  # cited by the analyst
        self.assertNotIn("cited", classes["evt_s1000003"])  # not cited

    def test_only_recent_events_are_fresh(self) -> None:
        events = queries.list_events(self.conn, "INC-001")
        newest = db.parse_iso(events[-1]["ts"])
        classes = marker_classes(self.build_map("INC-001", now=newest))
        self.assertIn("fresh", classes[events[-1]["event_id"]])
        self.assertNotIn("fresh", classes[events[0]["event_id"]])
        # Ten seconds later nothing is fresh any more.
        later = newest + timedelta(seconds=10)
        self.assertTrue(all("fresh" not in c for c in marker_classes(self.build_map("INC-001", now=later)).values()))

    def test_stage_columns_are_in_order_and_other_column_only_when_needed(self) -> None:
        map_html = self.build_map("INC-001")
        self.assertLess(map_html.index(">Source<"), map_html.index(">Build<"))
        self.assertLess(map_html.index(">Build<"), map_html.index(">Publish<"))
        self.assertIn("gk-cols-3", map_html)
        self.assertNotIn(">Other<", map_html)
        odd = dict(self.events[0], stage="unknown", routed_to="real")
        other_html = views.stage_map_html([odd], [], [], now=datetime.now(timezone.utc))
        self.assertIn(">Other<", other_html)
        self.assertIn("gk-cols-4", other_html)

    def test_empty_plane_collapses_to_a_one_line_note(self) -> None:
        inc1 = self.build_map("INC-001")
        self.assertIn("No traffic reached real services", inc1)
        self.assertNotIn("No traffic went to the decoy", inc1)
        inc2 = self.build_map("INC-002")
        self.assertIn("No traffic went to the decoy", inc2)
        self.assertNotIn("No traffic reached real services", inc2)

    def test_headings_and_both_planes_share_the_same_lanes(self) -> None:
        # Mixed traffic, so both planes are drawn with lanes.
        mixed = [dict(self.events[0], routed_to="real"), dict(self.events[1], routed_to="decoy")]
        map_html = views.stage_map_html(mixed, [], [], now=datetime.now(timezone.utc))
        self.assertEqual(map_html.count('class="gk-head"'), 3)
        self.assertEqual(map_html.count('<div class="gk-cell">'), 6)  # 3 lanes x 2 planes

    def test_blocked_event_sits_on_the_gateway(self) -> None:
        blocked = dict(self.events[0], routed_to="blocked")
        map_html = views.stage_map_html([blocked], [], [], now=datetime.now(timezone.utc))
        gateway_start = map_html.index('class="gk-gateway"')
        decoy_start = map_html.index('gk-plane gk-plane-decoy')
        self.assertTrue(gateway_start < map_html.index("gk-marker-blocked") < decoy_start)


class EscapingTests(unittest.TestCase):
    PAYLOAD = "<script>alert(1)</script>"

    def evil_event(self) -> dict:
        event = read_events(["scenario1"])[0]
        event.update(path=f"/x{self.PAYLOAD}", user_agent=self.PAYLOAD, target=self.PAYLOAD)
        return event

    def assert_escaped(self, html_text: str) -> None:
        self.assertNotIn("<script>", html_text)
        self.assertIn("&lt;script&gt;", html_text)

    def test_event_log_escapes_path_user_agent_and_target(self) -> None:
        self.assert_escaped(views.event_log_html([self.evil_event()]))

    def test_stage_map_escapes_target(self) -> None:
        html_text = views.stage_map_html([self.evil_event()], [], [], now=datetime.now(timezone.utc))
        self.assert_escaped(html_text)

    def test_other_views_escape_ids_and_analysis_text(self) -> None:
        incident = {
            "incident_id": "INC-001", "created_ts": "2026-10-25T10:00:00Z", "updated_ts": "2026-10-25T10:00:00Z",
            "signal_kind": "bait", "confidence": "high", "score": 60, "severity": "high", "status": "open",
            "source_ips": [self.PAYLOAD], "token_ids": [self.PAYLOAD], "stages": [],
            "rules_hit": [{"rule": self.PAYLOAD, "points": 60, "event_id": self.PAYLOAD}],
        }
        self.assert_escaped(views.detail_header_html(incident))
        self.assert_escaped(views.score_ledger_html(incident))
        body = {
            "summary": self.PAYLOAD, "observed": [self.PAYLOAD], "hypothesis": {"label": self.PAYLOAD, "confidence": "low"},
            "evidence_event_ids": [self.PAYLOAD], "alternatives": [{"label": self.PAYLOAD, "why": self.PAYLOAD}],
            "assets_at_risk": [self.PAYLOAD], "recommended_action": self.PAYLOAD, "limits": self.PAYLOAD,
        }
        analysis = {"source": "llm", "valid": 1, "based_on_event_count": 1, "body": body}
        self.assert_escaped(views.analyst_html(analysis, 1))
        action = {"kind": "revoke_credential", "target": self.PAYLOAD, "tier": "approval", "status": "approved",
                  "scope_ip": self.PAYLOAD, "mode": "block",
                  "decided_by": self.PAYLOAD, "decided_ts": "2026-10-25T10:00:00Z", "ts": "2026-10-25T10:00:00Z"}
        self.assert_escaped(views.pending_action_html(action))
        self.assert_escaped(views.auto_log_html([action]))


class AnalystPanelTests(DashboardTestCase):
    def test_arabic_blocks_are_right_to_left(self) -> None:
        analysis = queries.get_analysis(self.conn, "INC-001")
        panel = views.analyst_html(analysis, 5)
        rtl_blocks = re.findall(r'<p class="gk-ar [^"]*" dir="rtl" lang="ar">', panel)
        # summary, recommended action, limits, plus one block per alternative
        self.assertEqual(len(rtl_blocks), 3 + len(analysis["body"]["alternatives"]))
        self.assertIn(analysis["body"]["summary"], panel)
        self.assertIn("Package publish attempt", panel)
        self.assertIn("Automated secret scanner", panel)
        self.assertIn("LLM analyst", panel)

    def test_missing_analysis_says_pending(self) -> None:
        self.assertIn("Analysis pending", views.analyst_html(None, 3))

    def test_invalid_analysis_and_stale_count_are_flagged(self) -> None:
        analysis = queries.get_analysis(self.conn, "INC-001")
        analysis.update(valid=0, source="rules", based_on_event_count=2)
        panel = views.analyst_html(analysis, 5)
        self.assertIn("failed validation", panel)
        self.assertIn("Updating with new events", panel)
        self.assertIn("Rules-only analyst", panel)


class ResponseAndHeaderTests(DashboardTestCase):
    def test_pending_sentence_and_decided_line(self) -> None:
        action = queries.list_actions(self.conn, "INC-002")[1]
        self.assertIn("Stop REAL-CI-01 from 172.30.0.77 at our gateway", views.pending_action_html(action))
        queries.decide_action(self.conn, action["action_id"], "block", "hadi")
        decided = [a for a in queries.list_actions(self.conn, "INC-002") if a["kind"] == "revoke_credential"][0]
        log = views.auto_log_html(queries.list_actions(self.conn, "INC-002"))
        self.assertIn("Blocked at our gateway: REAL-CI-01 from 172.30.0.77 · 0 requests stopped since", log)
        self.assertIn("UTC", log)
        self.assertIn("Notified security-team", log)
        self.assertNotIn("pending", views.auto_log_html([dict(decided, status="pending")]))

    def test_auto_log_lists_disabled_baits(self) -> None:
        log = views.auto_log_html(queries.list_actions(self.conn, "INC-001"))
        self.assertIn("Disabled bait BAIT-SRC-01", log)
        self.assertIn("Disabled bait BAIT-CI-02", log)

    def test_header_shows_traffic_numbers_and_brand_lockup(self) -> None:
        header = views.header_html(queries.traffic_counts(self.conn), "data:image/svg+xml;base64,AAAA")
        self.assertIn("GHOSTKEY", header)
        self.assertIn('dir="rtl" lang="ar">فخ سلسلة الإمداد<', header)
        self.assertIn('<img src="data:image/svg+xml;base64,AAAA"', header)
        self.assertIn("<b>10</b> events seen", header)
        self.assertIn("<b>5</b> to decoy", header)
        self.assertIn("<b>2</b> open incidents", header)
        self.assertIn("Live, refreshes every 2s", header)

    def test_rail_label_marks_pending_approval(self) -> None:
        incident = queries.list_incidents(self.conn)[0]
        self.assertIn("Approval pending", views.rail_label(incident, 1))
        self.assertNotIn("Approval pending", views.rail_label(incident, 0))

    def test_headline(self) -> None:
        inc1 = queries.list_incidents(self.conn)[1]
        self.assertEqual(views.incident_headline(inc1), "Critical bait incident from 172.30.0.66")

    def test_html_builders_emit_no_blank_lines(self) -> None:
        # Streamlit's markdown parser would cut an HTML block at a blank line.
        incident = queries.list_incidents(self.conn)[0]
        events = queries.list_events(self.conn, incident["incident_id"])
        analysis = queries.get_analysis(self.conn, incident["incident_id"])
        pieces = [
            views.detail_header_html(incident),
            views.stage_map_html(events, incident["rules_hit"], []),
            views.score_ledger_html(incident),
            views.analyst_html(analysis, len(events)),
            views.event_log_html(events),
            views.empty_state_html(),
            views.funnel_html(queries.triage_funnel(self.conn)),
            views.no_traffic_html(),
            views.sessions_html(queries.list_sessions(self.conn)),
            views.activity_html(queries.list_all_events(self.conn)),
            views.all_events_html(queries.list_all_events(self.conn), len(self.events)),
        ]
        for piece in pieces:
            self.assertNotIn("\n\n", piece)


class TriageTests(DashboardTestCase):
    def session_for(self, **match: str) -> dict:
        sessions = queries.list_sessions(self.conn)
        return next(s for s in sessions if all(s[k] == v for k, v in match.items()))

    def add_flagged_event(self, ip: str = "172.30.0.99", **overrides: str) -> dict:
        """A real-token event with one signal and no incident (deviation below the threshold)."""
        event = dict(self.events[0], event_id="evt_f0000001", source_ip=ip, session_id="s_flagged1",
                     incident_id=None, processed=1, **overrides)
        db.insert_event(self.conn, event)
        self.conn.execute(
            "INSERT INTO signals (ts, event_id, token_id, rule, points, incident_id) VALUES (?,?,?,?,?,NULL)",
            (event["ts"], event["event_id"], "REAL-CI-01", "new_source", 20),
        )
        self.conn.commit()
        return event

    def test_funnel_numbers_come_from_the_fixtures(self) -> None:
        funnel = queries.triage_funnel(self.conn)
        in_incidents = self.conn.execute("SELECT COUNT(*) FROM events WHERE incident_id IS NOT NULL").fetchone()[0]
        analyses = self.conn.execute("SELECT COUNT(*) FROM analyses").fetchone()[0]
        llm = self.conn.execute("SELECT COUNT(*) FROM analyses WHERE source='llm' AND valid=1").fetchone()[0]
        self.assertEqual(funnel["requests"], len(self.events))
        self.assertEqual(funnel["in_incidents"], in_incidents)
        self.assertEqual(funnel["passed"] + funnel["flagged"] + funnel["in_incidents"], funnel["requests"])
        self.assertEqual(funnel["incidents"], 2)
        self.assertEqual(funnel["analyzed"], analyses)
        self.assertEqual(funnel["analyzed_llm"], llm)
        # The two normal events pass silently; nothing is flagged-only.
        self.assertEqual(funnel["passed"], 2)
        self.assertEqual(funnel["flagged"], 0)

    def test_normal_session_is_quiet_and_sorts_last(self) -> None:
        sessions = queries.list_sessions(self.conn)
        normal = self.session_for(source_ip="172.30.0.10", token="REAL-CI-01")
        self.assertEqual(normal["points"], 0)
        self.assertIsNone(normal["incident_id"])
        self.assertEqual(normal["requests"], 2)
        self.assertEqual(views.session_verdict(normal)[0], "normal")
        self.assertEqual(sessions[-1]["session_id"], normal["session_id"])

    def test_incident_sessions_come_first(self) -> None:
        sessions = queries.list_sessions(self.conn)
        # Fixture files carry no incident_id; use the DB, which fake core filled in.
        rows = self.conn.execute("SELECT DISTINCT session_id FROM events WHERE incident_id IS NOT NULL").fetchall()
        incident_sessions = {r["session_id"] for r in rows}
        self.assertTrue(incident_sessions)
        leading = sessions[: len(incident_sessions)]
        self.assertEqual({s["session_id"] for s in leading}, incident_sessions)
        for session in leading:
            self.assertEqual(views.session_verdict(session)[0], "incident")
        scenario2 = self.session_for(source_ip="172.30.0.77")
        self.assertEqual(scenario2["incident_id"], "INC-002")
        self.assertEqual(scenario2["points"], 80)
        self.assertEqual(views.session_verdict(scenario2), ("incident", "Incident INC-002"))

    def test_flagged_event_counts_and_gets_a_flagged_verdict(self) -> None:
        before = queries.triage_funnel(self.conn)
        self.add_flagged_event()
        after = queries.triage_funnel(self.conn)
        self.assertEqual(after["flagged"], before["flagged"] + 1)
        self.assertEqual(after["passed"], before["passed"])
        self.assertEqual(after["passed"] + after["flagged"] + after["in_incidents"], after["requests"])
        session = self.session_for(source_ip="172.30.0.99")
        self.assertEqual(session["points"], 20)
        self.assertEqual(views.session_verdict(session), ("flagged", "Flagged, below threshold"))
        sessions = queries.list_sessions(self.conn)
        flagged_at = [s["session_id"] for s in sessions].index(session["session_id"])
        normal_at = [s["session_id"] for s in sessions].index(self.session_for(source_ip="172.30.0.10")["session_id"])
        self.assertLess(flagged_at, normal_at)

    def test_repeated_hit_in_an_incident_session_is_not_passed_silently(self) -> None:
        """Core leaves a repeated rule hit without incident_id and signal; the session still owns it."""
        before = queries.triage_funnel(self.conn)
        first = dict(self.events[0], event_id="evt_r0000001", source_ip="172.30.0.88", session_id="s_attack88",
                     incident_id="INC-002", processed=1)
        follow_up = dict(first, event_id="evt_r0000002", incident_id=None)
        db.insert_event(self.conn, first)
        db.insert_event(self.conn, follow_up)
        self.conn.commit()
        after = queries.triage_funnel(self.conn)
        self.assertEqual(after["in_incidents"], before["in_incidents"] + 2)
        self.assertEqual(after["passed"], before["passed"])
        self.assertEqual(after["flagged"], before["flagged"])
        self.assertEqual(after["passed"] + after["flagged"] + after["in_incidents"], after["requests"])
        session = self.session_for(session_id="s_attack88")
        self.assertEqual(session["requests"], 2)
        self.assertEqual(views.session_verdict(session)[0], "incident")

    def test_funnel_matches_the_sessions_table(self) -> None:
        self.add_flagged_event()
        funnel = queries.triage_funnel(self.conn)
        sessions = queries.list_sessions(self.conn)
        incident_requests = sum(s["requests"] for s in sessions if s["incident_id"])
        flagged_requests = sum(s["requests"] for s in sessions if not s["incident_id"] and s["points"] > 0)
        self.assertEqual(funnel["in_incidents"], incident_requests)
        self.assertEqual(funnel["flagged"], flagged_requests)

    def test_unscored_verdict_for_non_real_sessions(self) -> None:
        session = {"incident_id": None, "points": 0, "token_kind": "unknown"}
        self.assertEqual(views.session_verdict(session), ("unscored", "No signals"))

    def test_funnel_html_shows_the_steps_and_the_note(self) -> None:
        funnel = queries.triage_funnel(self.conn)
        panel = views.funnel_html(funnel)
        self.assertIn("Traffic triage", panel)
        for label in ("requests checked", "passed silently", "flagged, watched", "incidents", "analyzed"):
            self.assertIn(label, panel)
        self.assertIn(f"{funnel['in_incidents']} requests", panel)
        self.assertIn(f"{funnel['analyzed_llm']} by LLM", panel)
        self.assertIn("Every request gets a cheap baseline check. Only incidents go to the analyst.", panel)
        self.assertNotIn("<table", panel)
        self.assertNotIn("\n\n", panel)

    def test_sessions_html_lists_every_session_with_last_seen(self) -> None:
        sessions = queries.list_sessions(self.conn)
        panel = views.sessions_html(sessions)
        self.assertIn("gk-pill-incident", panel)
        self.assertIn("gk-pill-normal", panel)
        self.assertIn("Last seen", panel)
        self.assertEqual(panel.count("<tr><td>"), len(sessions))
        self.assertIn(views.fmt_time(sessions[0]["last_ts"]), panel)
        self.assertNotIn("\n\n", panel)

    def test_sessions_html_has_no_row_cap(self) -> None:
        sessions = [
            {"session_id": f"s_{n}", "source_ip": f"10.0.0.{n}", "token": "anonymous", "token_kind": "none",
             "requests": 1, "points": 0, "incident_id": None, "last_ts": "2026-10-25T10:00:00Z"}
            for n in range(25)
        ]
        panel = views.sessions_html(sessions)
        self.assertEqual(panel.count("<tr><td>"), 25)
        self.assertNotIn("more sessions", panel)

    def test_sessions_html_escapes_hostile_values(self) -> None:
        payload = "<script>alert(1)</script>"
        session = {"session_id": "s_x", "source_ip": payload, "token": payload, "token_kind": "real",
                   "requests": 1, "points": 0, "incident_id": payload, "last_ts": "2026-10-25T10:00:00Z"}
        panel = views.sessions_html([session])
        self.assertNotIn("<script>", panel)
        self.assertIn("&lt;script&gt;", panel)
        self.assertNotIn("\n\n", panel)

    def test_empty_db_shows_the_no_traffic_line(self) -> None:
        with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
            conn = db.connect(Path(tmp) / "empty.db")
            try:
                db.init(conn)
                funnel = queries.triage_funnel(conn)
                self.assertEqual(funnel, {k: 0 for k in funnel})
                self.assertEqual(queries.list_sessions(conn), [])
                self.assertEqual(queries.list_all_events(conn), [])
                panel = views.no_traffic_html()
            finally:
                conn.close()
        self.assertIn("No traffic yet", panel)
        self.assertNotIn("requests checked", panel)
        self.assertNotIn("\n\n", panel)


class AllEventsQueryTests(DashboardTestCase):
    def test_newest_first_with_points(self) -> None:
        events = queries.list_all_events(self.conn)
        self.assertEqual(len(events), len(self.events))
        stamps = [e["ts"] for e in events]
        self.assertEqual(stamps, sorted(stamps, reverse=True))
        for column in ("event_id", "session_id", "source_ip", "user_agent", "routed_to", "incident_id", "path"):
            self.assertIn(column, events[0])
        expected = {
            row["event_id"]: row["points"]
            for row in self.conn.execute("SELECT event_id, SUM(points) AS points FROM signals GROUP BY event_id")
        }
        self.assertTrue(expected)
        for event in events:
            self.assertEqual(event["points"], expected.get(event["event_id"], 0))
        self.assertEqual(sum(e["points"] for e in events), sum(expected.values()))

    def test_limit_keeps_the_newest(self) -> None:
        everything = queries.list_all_events(self.conn)
        newest = queries.list_all_events(self.conn, limit=3)
        self.assertEqual([e["event_id"] for e in newest], [e["event_id"] for e in everything[:3]])


class EventFactoryTestCase(unittest.TestCase):
    """Three hand-made events (plain real, bait in an incident, flagged without incident)."""

    @staticmethod
    def make(n: int, **overrides: object) -> dict:
        event = {
            "event_id": f"evt_{n:08d}", "ts": f"2026-10-25T10:00:{n:02d}Z", "session_id": "s_x",
            "source_ip": "172.30.0.10", "user_agent": "npm/10", "token_kind": "real", "bait_id": None,
            "credential_id": "REAL-CI-01", "stage": "build", "service": "npm", "method": "GET",
            "path": "/@kfu/build-utils", "action": "install", "target": "@kfu/build-utils",
            "status_code": 200, "result": "ok", "routed_to": "real", "incident_id": None, "processed": 1,
            "points": 0,
        }
        event.update(overrides)
        return event

    def setUp(self) -> None:
        self.real = self.make(1)
        self.bait = self.make(2, token_kind="bait", bait_id="BAIT-SRC-01", credential_id=None, stage="source",
                              service="git", routed_to="decoy", incident_id="INC-001", points=60,
                              source_ip="172.30.0.66", user_agent="git/2.43", path="/ops/ci-pipeline.git",
                              target="ops/ci-pipeline")
        self.flagged = self.make(3, source_ip="172.30.0.77", points=20, routed_to="blocked", stage="publish")
        self.events = [self.real, self.bait, self.flagged]


class FilterEventsTests(EventFactoryTestCase):
    def ids(self, filters: dict) -> list[str]:
        return [e["event_id"] for e in queries.filter_events(self.events, filters)]

    def test_no_filters_keeps_everything_in_order(self) -> None:
        self.assertEqual(self.ids({}), [e["event_id"] for e in self.events])
        empty = {"routed_to": [], "token_kind": [], "service": [], "stage": [], "linked": "All", "search": ""}
        self.assertEqual(self.ids(empty), [e["event_id"] for e in self.events])

    def test_multiselect_filters(self) -> None:
        self.assertEqual(self.ids({"routed_to": ["decoy"]}), [self.bait["event_id"]])
        self.assertEqual(self.ids({"routed_to": ["real", "blocked"]}), [self.real["event_id"], self.flagged["event_id"]])
        self.assertEqual(self.ids({"token_kind": ["bait"]}), [self.bait["event_id"]])
        self.assertEqual(self.ids({"service": ["git"]}), [self.bait["event_id"]])
        self.assertEqual(self.ids({"stage": ["publish"]}), [self.flagged["event_id"]])
        self.assertEqual(self.ids({"service": ["npm"], "stage": ["build"]}), [self.real["event_id"]])

    def test_linked_filter(self) -> None:
        self.assertEqual(self.ids({"linked": queries.LINKED_IN_INCIDENT}), [self.bait["event_id"]])
        self.assertEqual(self.ids({"linked": queries.LINKED_NOT_IN_INCIDENT}),
                         [self.real["event_id"], self.flagged["event_id"]])
        self.assertEqual(self.ids({"linked": queries.LINKED_FLAGGED}), [self.bait["event_id"], self.flagged["event_id"]])

    def test_search_is_case_insensitive_over_the_listed_fields(self) -> None:
        self.assertEqual(self.ids({"search": "172.30.0.77"}), [self.flagged["event_id"]])
        self.assertEqual(self.ids({"search": "bait-src"}), [self.bait["event_id"]])
        self.assertEqual(self.ids({"search": "real-ci-01"}), [self.real["event_id"], self.flagged["event_id"]])
        self.assertEqual(self.ids({"search": "OPS/CI"}), [self.bait["event_id"]])
        self.assertEqual(self.ids({"search": "ci-pipeline.git"}), [self.bait["event_id"]])
        self.assertEqual(self.ids({"search": "GIT/2.43"}), [self.bait["event_id"]])
        self.assertEqual(self.ids({"search": "inc-001"}), [self.bait["event_id"]])
        self.assertEqual(self.ids({"search": self.flagged["event_id"].upper()}), [self.flagged["event_id"]])
        self.assertEqual(self.ids({"search": "  "}), [e["event_id"] for e in self.events])

    def test_no_match_gives_an_empty_list(self) -> None:
        self.assertEqual(self.ids({"search": "nothing-like-this"}), [])
        self.assertEqual(self.ids({"routed_to": ["decoy"], "stage": ["publish"]}), [])

    def test_filters_combine_with_and(self) -> None:
        self.assertEqual(self.ids({"routed_to": ["real", "decoy"], "search": "172.30.0.66"}), [self.bait["event_id"]])


class AllEventsHtmlTests(EventFactoryTestCase):
    PAYLOAD = "<script>alert(1)</script>"

    def test_header_line_counts_matches_and_total(self) -> None:
        panel = views.all_events_html(self.events, total=3)
        self.assertIn("Showing 3 of 3 events", panel)
        self.assertEqual(panel.count("<tr"), 1 + 3)
        panel = views.all_events_html(self.events[:2], total=3)
        self.assertIn("Showing 2 of 2 events", panel)

    def test_header_line_mentions_the_fetch_limit_and_the_draw_limit(self) -> None:
        panel = views.all_events_html(self.events, total=5000, fetched=3)
        self.assertIn("Only the newest 3 of 5000 events are loaded", panel)
        panel = views.all_events_html(self.events, total=3, shown_limit=2)
        self.assertIn("Showing 2 of 3 events", panel)
        self.assertEqual(panel.count("<tr"), 1 + 2)

    def test_nothing_matches_shows_a_quiet_line(self) -> None:
        panel = views.all_events_html([], total=3)
        self.assertIn("No events match these filters", panel)
        self.assertIn("Showing 0 of 0 events", panel)
        self.assertNotIn("<table", panel)

    def test_row_classes_for_incident_and_flagged(self) -> None:
        panel = views.all_events_html(self.events, total=3)
        self.assertEqual(panel.count('class="gk-ev-incident"'), 1)
        self.assertEqual(panel.count('class="gk-ev-flagged"'), 1)
        # A plain row carries no row class.
        self.assertIn("<tr><td>10:00:01</td>", panel)
        # An event in an incident wins over flagged even when it has points.
        self.assertIn('<tr class="gk-ev-incident"><td>10:00:02</td>', panel)

    def test_cells_show_token_result_routed_points_and_incident(self) -> None:
        panel = views.all_events_html(self.events, total=3)
        self.assertIn("BAIT-SRC-01", panel)
        self.assertIn("ok 200", panel)
        self.assertIn("gk-routed-decoy", panel)
        self.assertIn("gk-routed-blocked", panel)
        self.assertIn("<td>60</td>", panel)
        self.assertIn("<td>INC-001</td>", panel)
        self.assertIn('title="/ops/ci-pipeline.git"', panel)

    def test_hostile_values_are_escaped_in_text_and_title(self) -> None:
        evil = self.make(9, path=f'/x"{self.PAYLOAD}', user_agent=self.PAYLOAD, target=self.PAYLOAD,
                         source_ip=self.PAYLOAD, incident_id=self.PAYLOAD, credential_id=self.PAYLOAD)
        panel = views.all_events_html([evil], total=1)
        self.assertNotIn("<script>", panel)
        self.assertIn("&lt;script&gt;", panel)
        self.assertIn(f'title="{views.esc(self.PAYLOAD)}"', panel)
        # The quote in the path must not close the title attribute.
        self.assertIn("/x&quot;&lt;script&gt;", panel)
        self.assertNotIn('title="/x"', panel)

    def test_no_blank_lines(self) -> None:
        for panel in (
            views.all_events_html(self.events, total=3),
            views.all_events_html([], total=0),
        ):
            self.assertNotIn("\n\n", panel)


class ActivityHtmlTests(EventFactoryTestCase):
    NOW = datetime(2026, 10, 25, 10, 30, 20, tzinfo=timezone.utc)

    def at(self, minutes_ago: int, routed_to: str = "real", seconds: int = 0) -> dict:
        stamp = self.NOW.replace(second=0) - timedelta(minutes=minutes_ago) + timedelta(seconds=seconds)
        return self.make(1, ts=stamp.strftime("%Y-%m-%dT%H:%M:%SZ"), routed_to=routed_to)

    def test_buckets_count_events_per_minute_and_plane(self) -> None:
        events = [
            self.at(0, "real"), self.at(0, "real", seconds=15), self.at(0, "decoy"),
            self.at(5, "blocked"), self.at(29, "real"),
        ]
        buckets = views._activity_buckets(events, self.NOW, 30)
        self.assertEqual(len(buckets), 30)
        self.assertEqual(buckets[-1], {"real": 2, "decoy": 1, "blocked": 0})
        self.assertEqual(buckets[-1 - 5], {"real": 0, "decoy": 0, "blocked": 1})
        self.assertEqual(buckets[0], {"real": 1, "decoy": 0, "blocked": 0})
        self.assertEqual(sum(sum(b.values()) for b in buckets), 5)

    def test_events_outside_the_window_are_left_out(self) -> None:
        old = self.at(30, "real")
        future = self.at(-2, "real")
        buckets = views._activity_buckets([old, future], self.NOW, 30)
        self.assertEqual(sum(sum(b.values()) for b in buckets), 0)

    def test_html_has_one_slot_per_minute_and_totals_in_the_legend(self) -> None:
        events = [self.at(0, "real"), self.at(0, "decoy"), self.at(1, "decoy"), self.at(40, "decoy")]
        panel = views.activity_html(events, now=self.NOW)
        self.assertEqual(panel.count("<li title="), 30)
        self.assertIn("Real <b>1</b>", panel)
        self.assertIn("Decoy <b>2</b>", panel)
        self.assertIn("Blocked <b>0</b>", panel)
        self.assertIn("10:30 UTC: 2 events (1 real, 1 decoy)", panel)
        self.assertIn("10:01 UTC", panel)
        self.assertEqual(panel.count('class="gk-stack"'), 2)
        # The tallest minute fills the bar; the quieter one is shorter.
        self.assertIn("height:100%", panel)
        self.assertIn("height:50%", panel)

    def test_empty_minutes_have_no_stack(self) -> None:
        panel = views.activity_html([], now=self.NOW)
        self.assertEqual(panel.count("<li title="), 30)
        self.assertNotIn("gk-stack", panel)
        self.assertIn("Real <b>0</b>", panel)

    def test_minutes_parameter_changes_the_window(self) -> None:
        panel = views.activity_html([self.at(10)], now=self.NOW, minutes=10)
        self.assertEqual(panel.count("<li title="), 10)
        self.assertIn("Real <b>0</b>", panel)

    def test_no_blank_lines(self) -> None:
        self.assertNotIn("\n\n", views.activity_html([self.at(0)], now=self.NOW))


class EvidencePanelTests(DashboardTestCase):
    PAYLOAD = "<script>alert(1)</script>"

    def panels(self, incident_id: str) -> tuple[str, str, str]:
        incident = next(i for i in queries.list_incidents(self.conn) if i["incident_id"] == incident_id)
        events = queries.list_events(self.conn, incident_id)
        baselines = db.load_json("baselines.json")
        credentials = db.load_json("credentials.json")
        sessions = queries.list_sessions(self.conn)
        return (
            views.reached_real_html(events),
            views.baseline_html(incident, events, baselines, credentials),
            views.elsewhere_html(incident, sessions),
        )

    def test_scenario2_reached_real_lists_the_publish_as_written(self) -> None:
        reached, _, _ = self.panels("INC-002")
        self.assertIn("Written to the real npm", reached)
        self.assertIn("@kfu/build-utils", reached)
        self.assertIn("Read from the real npm", reached)
        self.assertIn("@kfu/payments-sdk", reached)
        self.assertIn("Ghostkey does not delete anything", reached)
        self.assertLess(reached.index("Written to"), reached.index("Read from"))

    def test_scenario1_reached_nothing_real(self) -> None:
        reached, _, _ = self.panels("INC-001")
        self.assertIn("Nothing reached the real services", reached)
        self.assertNotIn("Written to", reached)
        self.assertNotIn("Ghostkey does not delete anything", reached)

    def test_reached_real_ignores_decoy_blocked_and_failed_requests(self) -> None:
        base = dict(self.events[0], service="git", action="push", target="ops/x", result="ok", routed_to="real")
        for changes in ({"routed_to": "decoy"}, {"routed_to": "blocked"}, {"result": "denied"}, {"result": "error"}):
            self.assertIn("Nothing reached", views.reached_real_html([dict(base, **changes)]))
        self.assertIn("Written to the real git", views.reached_real_html([base]))

    def test_reached_real_groups_by_target_with_count_and_first_time(self) -> None:
        base = dict(self.events[0], service="npm", action="install", target="@kfu/a", result="ok", routed_to="real")
        events = [dict(base, ts="2026-10-25T10:00:09Z"), dict(base, ts="2026-10-25T10:00:03Z")]
        panel = views.reached_real_html(events)
        self.assertEqual(panel.count("@kfu/a"), 1)
        self.assertIn("2 requests, first at 10:00:03 UTC", panel)

    def test_nothing_reached_text_depends_on_what_really_happened(self) -> None:
        base = dict(self.events[0], service="npm", action="publish", target="@kfu/a", result="ok")
        decoy = [dict(base, routed_to="decoy"), dict(base, routed_to="decoy")]
        panel = views.reached_real_html(decoy)
        self.assertIn("Nothing reached the real services — every request went to the decoy", panel)

        blocked = [dict(base, routed_to="blocked", result="denied") for _ in range(2)]
        panel = views.reached_real_html(blocked)
        self.assertIn("Nothing reached the real services.", panel)
        self.assertIn("2 requests were blocked at our gateway.", panel)
        self.assertNotIn("every request went to the decoy", panel)

        denied = [dict(base, routed_to="real", result="denied", status_code=401)]
        panel = views.reached_real_html(denied)
        self.assertIn("Nothing reached the real services.", panel)
        self.assertNotIn("every request went to the decoy", panel)
        self.assertNotIn("blocked at our gateway", panel)
        self.assertNotIn("\n\n", panel)

    def test_baseline_marks_only_values_outside_the_baseline(self) -> None:
        _, baseline, _ = self.panels("INC-002")
        for value in ("172.30.0.77", "@kfu/payments-sdk", "publish"):
            self.assertIn(f'<li class="gk-out">{value}</li>', baseline)
        for value in ("install", "@kfu/build-utils", "172.30.0.10"):
            self.assertNotIn(f'<li class="gk-out">{value}</li>', baseline)
        self.assertIn('<p class="gk-out">yes</p>', baseline)
        self.assertIn("not allowed", baseline)
        self.assertIn("ci-bot", baseline)
        self.assertIn("npm", baseline)
        self.assertNotIn("sha256", baseline)
        for credential in db.load_json("credentials.json"):
            self.assertNotIn(credential["sha256"], baseline)
            self.assertNotIn(credential["note"], baseline)

    def test_baseline_publishing_row_is_calm_when_nothing_was_published(self) -> None:
        incident = {"incident_id": "INC-009", "token_ids": ["REAL-CI-01"]}
        event = dict(self.events[0], token_kind="real", credential_id="REAL-CI-01", source_ip="172.30.0.10",
                     action="install", target="@kfu/build-utils")
        panel = views.baseline_html(incident, [event], db.load_json("baselines.json"), db.load_json("credentials.json"))
        self.assertNotIn("gk-out", panel)
        self.assertIn("<p>no</p>", panel)

    def test_baseline_is_empty_without_a_real_credential_with_a_baseline(self) -> None:
        _, baseline, _ = self.panels("INC-001")
        self.assertEqual(baseline, "")
        incident = {"incident_id": "INC-009", "token_ids": ["REAL-OTHER"]}
        event = dict(self.events[0], token_kind="real", credential_id="REAL-OTHER")
        self.assertEqual(views.baseline_html(incident, [event], db.load_json("baselines.json"), []), "")

    def test_elsewhere_lists_the_normal_ci_runner_session(self) -> None:
        _, _, elsewhere = self.panels("INC-002")
        self.assertIn("172.30.0.10", elsewhere)
        self.assertIn("Containment applies only to the attacker's IP, so these keep working.", elsewhere)
        self.assertIn("gk-pill-normal", elsewhere)
        self.assertNotIn("172.30.0.77", elsewhere)

    def test_elsewhere_is_empty_when_it_does_not_apply(self) -> None:
        _, _, elsewhere = self.panels("INC-001")
        self.assertEqual(elsewhere, "")

    def test_diverted_real_events_are_not_counted_as_reached_real(self) -> None:
        # A reviewer diverted the real token: token_kind stays real, but the request went to the decoy.
        event = dict(self.events[0], token_kind="real", credential_id="REAL-CI-01", routed_to="decoy",
                     action="publish", service="npm", target="@kfu/build-utils", result="ok")
        self.assertIn("Nothing reached", views.reached_real_html([event]))

    def test_hostile_values_are_escaped_and_single_line(self) -> None:
        event = dict(self.events[0], token_kind="real", credential_id="REAL-CI-01", source_ip=self.PAYLOAD,
                     target=self.PAYLOAD, service="npm", action="publish", result="ok", routed_to="real")
        incident = {"incident_id": "INC-009", "token_ids": ["REAL-CI-01"]}
        credentials = [{"credential_id": "REAL-CI-01", "service": self.PAYLOAD, "owner": self.PAYLOAD}]
        session = {"session_id": "s_x", "source_ip": self.PAYLOAD, "token": "REAL-CI-01", "token_kind": "real",
                   "requests": 1, "points": 0, "incident_id": self.PAYLOAD, "last_ts": "2026-10-25T10:00:00Z"}
        panels = [
            views.reached_real_html([event]),
            views.baseline_html(incident, [event], db.load_json("baselines.json"), credentials),
            views.elsewhere_html(incident, [session]),
        ]
        for panel in panels:
            self.assertNotIn("<script>", panel)
            self.assertIn("&lt;script&gt;", panel)
            self.assertNotIn("\n\n", panel)

    def test_real_panels_emit_no_blank_lines(self) -> None:
        for incident_id in ("INC-001", "INC-002"):
            for panel in self.panels(incident_id):
                self.assertNotIn("\n\n", panel)


if __name__ == "__main__":
    unittest.main()

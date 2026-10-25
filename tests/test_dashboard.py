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

    def test_approve_pending_action(self) -> None:
        action_id = self.action_id("INC-002", "revoke_credential")
        self.assertTrue(queries.decide_action(self.conn, action_id, "approve", "hadi"))
        row = self.action_row(action_id)
        self.assertEqual(row["status"], "approved")
        self.assertEqual(row["decided_by"], "hadi")
        self.assertTrue(row["decided_ts"].endswith("Z"))

    def test_reject_pending_action(self) -> None:
        action_id = self.action_id("INC-002", "revoke_credential")
        self.assertTrue(queries.decide_action(self.conn, action_id, "reject", "ghalia"))
        self.assertEqual(self.action_row(action_id)["status"], "rejected")

    def test_decided_action_cannot_be_decided_again(self) -> None:
        action_id = self.action_id("INC-002", "revoke_credential")
        queries.decide_action(self.conn, action_id, "approve", "hadi")
        before = self.action_row(action_id)
        self.assertFalse(queries.decide_action(self.conn, action_id, "reject", "someone-else"))
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
        queries.decide_action(self.conn, action_id, "approve", "   ")
        self.assertEqual(self.action_row(action_id)["decided_by"], "analyst")

    def test_bad_decision_word_is_an_error(self) -> None:
        with self.assertRaises(ValueError):
            queries.decide_action(self.conn, 1, "maybe", "hadi")


def marker_classes(map_html: str) -> dict[str, str]:
    """event_id -> the class attribute of its marker."""
    return {m.group(2): m.group(1) for m in re.finditer(r'<article class="([^"]+)" data-event="([^"]+)"', map_html)}


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
        self.assertIn("Revoke credential REAL-CI-01", views.pending_action_html(action))
        queries.decide_action(self.conn, action["action_id"], "approve", "hadi")
        decided = [a for a in queries.list_actions(self.conn, "INC-002") if a["kind"] == "revoke_credential"][0]
        log = views.auto_log_html(queries.list_actions(self.conn, "INC-002"))
        self.assertIn("Approved by hadi at", log)
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
        ]
        for piece in pieces:
            self.assertNotIn("\n\n", piece)


if __name__ == "__main__":
    unittest.main()

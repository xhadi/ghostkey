"""Tests for brain/rules.py: the behavior rules (pure) and a run with the real core."""
from __future__ import annotations

import unittest

from common import db
from fixtures.load_fixtures import read_events
from brain.rules import behavior_hits
from tests.brain_support import BrainTestCase
from tests.test_core import expected_incident, make_event, real_event

BASELINE = db.load_json("baselines.json")["REAL-CI-01"]
EVENTS_BY_ID = {e["event_id"]: e for e in read_events(["normal", "scenario1", "scenario2"])}


def rule_names(hits: list[dict]) -> list[str]:
    return [hit["rule"] for hit in hits]


class FixtureEventTests(unittest.TestCase):
    """The five real-token fixture events against the REAL-CI-01 baseline (CLAUDE.md reference)."""

    def hits_for(self, event_id: str) -> list[dict]:
        return behavior_hits(EVENTS_BY_ID[event_id], BASELINE)

    def test_normal_login_has_no_hits(self) -> None:
        self.assertEqual(self.hits_for("evt_n0000001"), [])

    def test_normal_install_has_no_hits(self) -> None:
        self.assertEqual(self.hits_for("evt_n0000002"), [])

    def test_install_from_new_ip_is_new_source_only(self) -> None:
        self.assertEqual(self.hits_for("evt_s2000001"), [{"rule": "new_source", "points": 20}])

    def test_install_of_other_package_is_new_source_and_out_of_scope(self) -> None:
        self.assertEqual(self.hits_for("evt_s2000002"), [
            {"rule": "new_source", "points": 20},
            {"rule": "out_of_scope", "points": 25},
        ])

    def test_publish_from_new_ip_hits_all_three_rules_in_order(self) -> None:
        self.assertEqual(self.hits_for("evt_s2000003"), [
            {"rule": "new_source", "points": 20},
            {"rule": "out_of_scope", "points": 25},
            {"rule": "unexpected_publish", "points": 35},
        ])


class EdgeCaseTests(unittest.TestCase):
    def test_no_baseline_means_no_hits(self) -> None:
        event = real_event("evt_x1", "2026-10-25T10:00:00Z", source_ip="6.6.6.6", action="publish")
        self.assertEqual(behavior_hits(event, None), [])

    def test_event_without_target_is_not_out_of_scope(self) -> None:
        event = real_event("evt_x2", "2026-10-25T10:00:00Z", action="login", target=None)
        self.assertEqual(behavior_hits(event, BASELINE), [])

    def test_push_counts_as_unexpected_publish(self) -> None:
        event = real_event("evt_x3", "2026-10-25T10:00:00Z", action="push", target="ops/ci-pipeline",
                           service="git", stage="publish")
        self.assertEqual(rule_names(behavior_hits(event, BASELINE)), ["out_of_scope", "unexpected_publish"])

    def test_publish_is_allowed_when_baseline_says_may_publish(self) -> None:
        baseline = {**BASELINE, "may_publish": True, "allowed_actions": ["install", "publish"]}
        event = real_event("evt_x4", "2026-10-25T10:00:00Z", action="publish")
        self.assertEqual(behavior_hits(event, baseline), [])

    def test_action_outside_baseline_is_out_of_scope(self) -> None:
        event = real_event("evt_x5", "2026-10-25T10:00:00Z", action="search", target=None)
        self.assertEqual(rule_names(behavior_hits(event, BASELINE)), ["out_of_scope"])

    def test_does_not_change_its_inputs(self) -> None:
        event = make_event("evt_x6", "2026-10-25T10:00:00Z", token_kind="real", credential_id="REAL-CI-01",
                           source_ip="6.6.6.6", action="publish", target="@kfu/x")
        event_before, baseline_before = dict(event), {k: list(v) if isinstance(v, list) else v
                                                      for k, v in BASELINE.items()}
        behavior_hits(event, BASELINE)
        self.assertEqual(event, event_before)
        self.assertEqual(BASELINE, baseline_before)


class RealCoreIntegrationTests(BrainTestCase):
    """Run core.engine.process_pending with the real behavior rules over every fixture."""

    def setUp(self) -> None:
        super().setUp()
        self.load_fixtures("normal", "scenario1", "scenario2")
        self.run_core()

    def test_behavior_incident_matches_expected_state(self) -> None:
        want = expected_incident("INC-002")
        behavior = [i for i in self.incidents() if i["signal_kind"] == "behavior"]
        self.assertEqual(len(behavior), 1)
        got = behavior[0]
        for key in ("signal_kind", "confidence", "score", "severity", "status",
                    "source_ips", "token_ids", "stages", "rules_hit"):
            with self.subTest(field=key):
                self.assertEqual(got[key], want[key])

    def test_behavior_incident_holds_the_three_scenario2_events(self) -> None:
        self.assertEqual(self.event_ids_of("INC-002"), expected_incident("INC-002")["events"])

    def test_normal_traffic_stays_unattached_with_no_signals(self) -> None:
        rows = self.conn.execute(
            "SELECT event_id, incident_id FROM events WHERE event_id LIKE 'evt_n%'"
        ).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertTrue(all(row["incident_id"] is None for row in rows))
        normal_signals = self.conn.execute("SELECT * FROM signals WHERE event_id LIKE 'evt_n%'").fetchall()
        self.assertEqual(normal_signals, [])

    def test_bait_incident_is_unchanged_by_the_real_rules(self) -> None:
        self.assertEqual(self.incident("INC-001")["score"], 95)


if __name__ == "__main__":
    unittest.main()

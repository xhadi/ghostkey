"""Tests for brain/analyst_rules.py: the rules-only analysis must always be valid."""
from __future__ import annotations

import copy
import unittest

from brain.analyst_rules import rules_analysis
from brain.validate import validate
from tests.brain_support import BrainTestCase
from tests.test_core import at, make_event


def hand_made_incident(signal_kind: str, actions: list[tuple], rules_hit_indexes: list[int] | None = None,
                       token_id: str | None = None) -> tuple[dict, list[dict]]:
    """Build (incident, events) from (action, service, target) tuples, one event per minute.

    rules_hit_indexes picks which events (by position) appear in rules_hit.
    """
    is_bait = signal_kind == "bait"
    token_id = token_id or ("BAIT-X-01" if is_bait else "REAL-CI-01")
    events = []
    for number, (action, service, target) in enumerate(actions, start=1):
        events.append(make_event(
            f"evt_h{number:07d}", at(number), token_kind="bait" if is_bait else "real",
            bait_id=token_id if is_bait else None, credential_id=None if is_bait else token_id,
            service=service, action=action, target=target, source_ip="10.9.9.9",
            routed_to="decoy" if is_bait else "real", incident_id="INC-900",
        ))
    rules_hit = [{"rule": "bait_use" if is_bait else "new_source", "points": 20,
                  "event_id": events[i]["event_id"]} for i in (rules_hit_indexes or [])]
    incident = {
        "incident_id": "INC-900", "signal_kind": signal_kind,
        "confidence": "high" if is_bait else "medium", "score": 60, "severity": "medium",
        "status": "open" if is_bait else "needs_review", "source_ips": ["10.9.9.9"],
        "token_ids": [token_id], "stages": ["source"], "rules_hit": rules_hit,
    }
    return incident, events


def assert_valid(test: unittest.TestCase, incident: dict, events: list[dict]) -> dict:
    """Run rules_analysis and check it passes validate(). Returns the body."""
    body = rules_analysis(incident, events)
    test.assertEqual(validate(body, {e["event_id"] for e in events}), [])
    return body


def alternative_labels(body: dict) -> list[str]:
    return [alt["label"] for alt in body["alternatives"]]


class FixtureScenarioTests(BrainTestCase):
    """Incidents produced by the REAL core (with the real behavior rules) over the fixtures."""

    def setUp(self) -> None:
        super().setUp()
        self.load_fixtures("normal", "scenario1", "scenario2")
        self.run_core()

    def analysis_for(self, incident_id: str) -> tuple[dict, dict, list[dict]]:
        incident, events = self.incident(incident_id), self.events_of(incident_id)
        return assert_valid(self, incident, events), incident, events

    def test_scenario1_is_a_package_publish_bait_incident(self) -> None:
        body, _, _ = self.analysis_for("INC-001")
        self.assertEqual(body["hypothesis"], {"label": "package_publish", "confidence": "medium"})
        self.assertEqual(body["observed"], ["list_repos", "clone", "login", "publish"])

    def test_scenario1_evidence_stays_inside_the_incident_and_includes_the_publish(self) -> None:
        body, _, events = self.analysis_for("INC-001")
        self.assertTrue(set(body["evidence_event_ids"]) <= {e["event_id"] for e in events})
        self.assertIn("evt_s1000005", body["evidence_event_ids"])
        self.assertEqual(body["evidence_event_ids"], ["evt_s1000001", "evt_s1000004", "evt_s1000005"])

    def test_scenario1_alternative_is_the_automated_secret_scanner_and_notes_the_publish(self) -> None:
        body, _, _ = self.analysis_for("INC-001")
        self.assertIn("automated_secret_scanner", alternative_labels(body))
        scanner = next(a for a in body["alternatives"] if a["label"] == "automated_secret_scanner")
        self.assertIn("النشر", scanner["why"])

    def test_scenario1_assets_are_the_repo_and_the_internal_npm_package(self) -> None:
        body, _, _ = self.analysis_for("INC-001")
        self.assertEqual(body["assets_at_risk"],
                         ["git repo: ops/ci-pipeline", "internal npm registry: @kfu/build-utils"])

    def test_scenario1_text_mentions_the_baits_and_disabling_them(self) -> None:
        body, _, _ = self.analysis_for("INC-001")
        self.assertIn("BAIT-SRC-01", body["summary"])
        self.assertIn("BAIT-CI-02", body["summary"])
        self.assertIn("تعطيل الطعوم", body["recommended_action"])
        self.assertIn("@kfu/build-utils", body["recommended_action"])

    def test_scenario2_is_a_low_confidence_package_publish(self) -> None:
        body, _, _ = self.analysis_for("INC-002")
        self.assertEqual(body["hypothesis"], {"label": "package_publish", "confidence": "low"})
        self.assertEqual(body["observed"], ["install", "publish"])
        self.assertEqual(body["evidence_event_ids"], ["evt_s2000001", "evt_s2000002", "evt_s2000003"])

    def test_scenario2_alternative_is_unknown_and_mentions_a_developer(self) -> None:
        body, _, _ = self.analysis_for("INC-002")
        self.assertEqual(alternative_labels(body), ["unknown"])
        self.assertIn("مطوّر", body["alternatives"][0]["why"])

    def test_scenario2_assets_and_review_advice(self) -> None:
        body, _, _ = self.analysis_for("INC-002")
        self.assertEqual(body["assets_at_risk"], ["internal npm registry: @kfu/build-utils",
                                                  "internal npm registry: @kfu/payments-sdk"])
        self.assertIn("مراجعة بشرية", body["recommended_action"])
        self.assertIn("REAL-CI-01", body["recommended_action"])
        self.assertIn("@kfu/build-utils", body["recommended_action"])
        self.assertIn("إصدار", body["recommended_action"])
        self.assertNotIn("تعطيل الطعوم", body["recommended_action"])

    def test_limits_state_the_event_count_and_that_no_llm_was_used(self) -> None:
        body1, _, _ = self.analysis_for("INC-001")
        body2, _, _ = self.analysis_for("INC-002")
        self.assertIn("5 أحداث", body1["limits"])
        self.assertIn("3 أحداث", body2["limits"])
        for body in (body1, body2):
            self.assertIn("بدون نموذج لغوي", body["limits"])

    def test_same_input_gives_the_same_output(self) -> None:
        _, incident, events = self.analysis_for("INC-001")
        self.assertEqual(rules_analysis(incident, events), rules_analysis(incident, events))

    def test_inputs_are_not_changed(self) -> None:
        _, incident, events = self.analysis_for("INC-002")
        incident_before, events_before = copy.deepcopy(incident), copy.deepcopy(events)
        rules_analysis(incident, events)
        self.assertEqual(incident, incident_before)
        self.assertEqual(events, events_before)


class HypothesisLabelTests(unittest.TestCase):
    def label_of(self, signal_kind: str, actions: list[tuple]) -> str:
        incident, events = hand_made_incident(signal_kind, actions, [0])
        return assert_valid(self, incident, events)["hypothesis"]["label"]

    def test_publish_wins_over_clone(self) -> None:
        actions = [("clone", "git", "ops/a"), ("publish", "npm", "@kfu/x")]
        self.assertEqual(self.label_of("bait", actions), "package_publish")

    def test_push_is_a_package_publish(self) -> None:
        self.assertEqual(self.label_of("bait", [("clone", "git", "ops/a"), ("push", "git", "ops/a")]),
                         "package_publish")

    def test_clone_is_source_theft(self) -> None:
        self.assertEqual(self.label_of("bait", [("list_repos", "git", None), ("clone", "git", "ops/a")]),
                         "source_theft")

    def test_api_write_is_source_theft(self) -> None:
        self.assertEqual(self.label_of("bait", [("api_read", "git", None), ("api_write", "git", "ops/a")]),
                         "source_theft")

    def test_only_login_is_credential_harvest(self) -> None:
        self.assertEqual(self.label_of("bait", [("login", "npm", None), ("login", "npm", None)]),
                         "credential_harvest")

    def test_login_with_other_recon_actions_is_recon_only(self) -> None:
        self.assertEqual(self.label_of("bait", [("login", "npm", None), ("search", "npm", None)]),
                         "recon_only")

    def test_listing_and_reading_is_recon_only(self) -> None:
        actions = [("list_repos", "git", None), ("api_read", "git", "ops/a")]
        self.assertEqual(self.label_of("bait", actions), "recon_only")

    def test_install_only_behavior_is_recon_only(self) -> None:
        self.assertEqual(self.label_of("behavior", [("install", "npm", "@kfu/x")]), "recon_only")

    def test_only_other_actions_is_unknown(self) -> None:
        self.assertEqual(self.label_of("bait", [("other", "git", None)]), "unknown")


class ConfidenceAndAlternativeTests(unittest.TestCase):
    def test_bait_incident_has_medium_confidence_and_behavior_has_low(self) -> None:
        for kind, want in (("bait", "medium"), ("behavior", "low")):
            with self.subTest(kind=kind):
                incident, events = hand_made_incident(kind, [("install", "npm", "@kfu/x")], [0])
                body = assert_valid(self, incident, events)
                self.assertEqual(body["hypothesis"]["confidence"], want)

    def test_scanner_alternative_does_not_mention_a_write_when_there_was_none(self) -> None:
        incident, events = hand_made_incident("bait", [("list_repos", "git", None), ("clone", "git", "ops/a")], [0])
        scanner = assert_valid(self, incident, events)["alternatives"][0]
        self.assertEqual(scanner["label"], "automated_secret_scanner")
        self.assertNotIn("تضعف", scanner["why"])

    def test_scanner_alternative_mentions_a_write_for_api_write_and_push(self) -> None:
        for action in ("api_write", "push"):
            with self.subTest(action=action):
                incident, events = hand_made_incident("bait", [("clone", "git", "ops/a"),
                                                               (action, "git", "ops/a")], [0])
                scanner = assert_valid(self, incident, events)["alternatives"][0]
                self.assertIn("تضعف", scanner["why"])

    def test_behavior_incident_with_unknown_label_gets_a_different_alternative(self) -> None:
        incident, events = hand_made_incident("behavior", [("other", "npm", None)], [0])
        body = assert_valid(self, incident, events)
        self.assertEqual(body["hypothesis"]["label"], "unknown")
        self.assertNotIn("unknown", alternative_labels(body))

    def test_bait_incident_with_unknown_label_keeps_the_scanner_alternative(self) -> None:
        incident, events = hand_made_incident("bait", [("other", "npm", None)], [0])
        body = assert_valid(self, incident, events)
        self.assertEqual(alternative_labels(body), ["automated_secret_scanner"])


class EvidenceTests(unittest.TestCase):
    def test_evidence_is_rules_hit_events_plus_the_deciding_event_in_time_order(self) -> None:
        actions = [("list_repos", "git", None), ("clone", "git", "ops/a"), ("login", "npm", None),
                   ("publish", "npm", "@kfu/x"), ("publish", "npm", "@kfu/y")]
        incident, events = hand_made_incident("bait", actions, [2, 0, 2])
        body = assert_valid(self, incident, events)
        self.assertEqual(body["evidence_event_ids"], ["evt_h0000001", "evt_h0000003", "evt_h0000004"])

    def test_deciding_event_already_in_rules_hit_is_not_repeated(self) -> None:
        incident, events = hand_made_incident("bait", [("clone", "git", "ops/a")], [0])
        self.assertEqual(assert_valid(self, incident, events)["evidence_event_ids"], ["evt_h0000001"])

    def test_deciding_event_for_source_theft_is_the_first_clone(self) -> None:
        actions = [("list_repos", "git", None), ("clone", "git", "ops/a"), ("clone", "git", "ops/b")]
        incident, events = hand_made_incident("bait", actions, [0])
        self.assertEqual(assert_valid(self, incident, events)["evidence_event_ids"],
                         ["evt_h0000001", "evt_h0000002"])

    def test_empty_rules_hit_falls_back_to_the_first_event(self) -> None:
        incident, events = hand_made_incident("bait", [("other", "git", None), ("other", "git", None)], [])
        self.assertEqual(assert_valid(self, incident, events)["evidence_event_ids"], ["evt_h0000001"])

    def test_rules_hit_pointing_at_a_foreign_event_is_dropped(self) -> None:
        incident, events = hand_made_incident("bait", [("list_repos", "git", None)], [0])
        incident["rules_hit"].append({"rule": "bait_use", "points": 60, "event_id": "evt_foreign"})
        self.assertEqual(assert_valid(self, incident, events)["evidence_event_ids"], ["evt_h0000001"])


class ObservedAndAssetsTests(unittest.TestCase):
    def test_consecutive_duplicates_collapse_but_repeats_after_a_gap_stay(self) -> None:
        actions = [("install", "npm", "@kfu/a"), ("install", "npm", "@kfu/b"), ("publish", "npm", "@kfu/a"),
                   ("install", "npm", "@kfu/a")]
        incident, events = hand_made_incident("behavior", actions, [0])
        self.assertEqual(assert_valid(self, incident, events)["observed"], ["install", "publish", "install"])

    def test_other_is_dropped_before_collapsing(self) -> None:
        actions = [("install", "npm", "@kfu/a"), ("other", "npm", None), ("install", "npm", "@kfu/b")]
        incident, events = hand_made_incident("behavior", actions, [0])
        self.assertEqual(assert_valid(self, incident, events)["observed"], ["install"])

    def test_assets_are_distinct_targets_in_time_order_with_a_prefix_per_service(self) -> None:
        actions = [("clone", "git", "ops/b"), ("install", "npm", "@kfu/a"), ("clone", "git", "ops/b"),
                   ("login", "npm", None), ("clone", "git", "ops/a")]
        incident, events = hand_made_incident("bait", actions, [0])
        self.assertEqual(assert_valid(self, incident, events)["assets_at_risk"],
                         ["git repo: ops/b", "internal npm registry: @kfu/a", "git repo: ops/a"])

    def test_no_targets_means_no_assets(self) -> None:
        incident, events = hand_made_incident("bait", [("list_repos", "git", None)], [0])
        self.assertEqual(assert_valid(self, incident, events)["assets_at_risk"], [])


class ArabicTextTests(unittest.TestCase):
    def test_limits_count_words_for_small_numbers(self) -> None:
        cases = {1: "حدث واحد", 2: "حدثين", 3: "3 أحداث", 10: "10 أحداث", 11: "11 حدث"}
        for count, phrase in cases.items():
            with self.subTest(count=count):
                actions = [("list_repos", "git", None)] * count
                incident, events = hand_made_incident("bait", actions, [0])
                self.assertIn(phrase, assert_valid(self, incident, events)["limits"])

    def test_text_fields_are_arabic_and_keep_ids_in_english(self) -> None:
        incident, events = hand_made_incident("bait", [("list_repos", "git", None)], [0], token_id="BAIT-Z-09")
        body = assert_valid(self, incident, events)
        for key in ("summary", "recommended_action", "limits"):
            with self.subTest(key=key):
                self.assertTrue(any("؀" <= ch <= "ۿ" for ch in body[key]))
        self.assertIn("BAIT-Z-09", body["summary"])
        self.assertIn("BAIT-Z-09", body["recommended_action"])

    def test_behavior_advice_without_publish_does_not_talk_about_versions(self) -> None:
        incident, events = hand_made_incident("behavior", [("install", "npm", "@kfu/a")], [0])
        body = assert_valid(self, incident, events)
        self.assertIn("مراجعة بشرية", body["recommended_action"])
        self.assertNotIn("إصدار", body["recommended_action"])

    def test_push_advice_names_the_repo(self) -> None:
        incident, events = hand_made_incident("behavior", [("push", "git", "ops/a")], [0])
        self.assertIn("ops/a", assert_valid(self, incident, events)["recommended_action"])

    def test_summary_lists_the_ips(self) -> None:
        incident, events = hand_made_incident("behavior", [("install", "npm", "@kfu/a")], [0])
        self.assertIn("10.9.9.9", assert_valid(self, incident, events)["summary"])


if __name__ == "__main__":
    unittest.main()

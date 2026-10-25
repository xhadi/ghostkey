"""Tests for brain/validate.py: one test per rejection rule, plus the contract example."""
from __future__ import annotations

import copy
import unittest

from brain.validate import ALLOWED_LABELS, validate
from common import db

EXAMPLE = db.load_json("analysis.example.json")
SCENARIO1_EVENT_IDS = {f"evt_s100000{n}" for n in range(1, 6)}
REQUIRED_KEYS = ("summary", "observed", "hypothesis", "evidence_event_ids", "alternatives",
                 "assets_at_risk", "recommended_action", "limits")


def body_with(**changes) -> dict:
    """A fresh copy of the example body with some top-level keys replaced."""
    body = copy.deepcopy(EXAMPLE)
    body.update(changes)
    return body


class ValidateTestCase(unittest.TestCase):
    def errors(self, body) -> list[str]:
        return validate(body, SCENARIO1_EVENT_IDS)

    def assert_rejected_mentioning(self, body, text: str) -> None:
        errors = self.errors(body)
        self.assertTrue(errors, "expected at least one error")
        self.assertTrue(any(text in error for error in errors), f"no error mentions {text!r}: {errors}")


class ValidBodyTests(ValidateTestCase):
    def test_contract_example_is_valid_for_scenario1_events(self) -> None:
        self.assertEqual(self.errors(EXAMPLE), [])

    def test_every_allowed_label_is_accepted(self) -> None:
        for label in ALLOWED_LABELS:
            with self.subTest(label=label):
                body = body_with(hypothesis={"label": label, "confidence": "low"})
                self.assertEqual(self.errors(body), [])

    def test_allowed_labels_match_claude_md(self) -> None:
        self.assertEqual(set(ALLOWED_LABELS), {"recon_only", "source_theft", "package_publish",
                                               "credential_harvest", "automated_secret_scanner", "unknown"})

    def test_validate_does_not_change_the_body(self) -> None:
        body = body_with(evidence_event_ids=["evt_other"])
        before = copy.deepcopy(body)
        self.errors(body)
        self.assertEqual(body, before)


class MissingKeyTests(ValidateTestCase):
    def test_each_required_key_is_required(self) -> None:
        for key in REQUIRED_KEYS:
            with self.subTest(key=key):
                body = body_with()
                del body[key]
                self.assert_rejected_mentioning(body, key)

    def test_hypothesis_label_is_required(self) -> None:
        self.assert_rejected_mentioning(body_with(hypothesis={"confidence": "low"}), "hypothesis.label")

    def test_hypothesis_confidence_is_required(self) -> None:
        self.assert_rejected_mentioning(body_with(hypothesis={"label": "unknown"}), "hypothesis.confidence")

    def test_body_that_is_not_a_dict_is_rejected(self) -> None:
        for bad in (None, [], "text", 5):
            with self.subTest(body=bad):
                self.assertTrue(self.errors(bad))


class WrongTypeTests(ValidateTestCase):
    def test_string_fields_must_be_strings(self) -> None:
        for key in ("summary", "recommended_action", "limits"):
            with self.subTest(key=key):
                self.assert_rejected_mentioning(body_with(**{key: 5}), key)

    def test_list_fields_must_be_lists(self) -> None:
        for key in ("observed", "evidence_event_ids", "assets_at_risk", "alternatives"):
            with self.subTest(key=key):
                self.assert_rejected_mentioning(body_with(**{key: "not a list"}), key)

    def test_string_lists_must_hold_strings(self) -> None:
        for key in ("observed", "evidence_event_ids", "assets_at_risk"):
            with self.subTest(key=key):
                self.assert_rejected_mentioning(body_with(**{key: [5]}), key)

    def test_hypothesis_must_be_a_dict(self) -> None:
        self.assert_rejected_mentioning(body_with(hypothesis="package_publish"), "hypothesis")


class HypothesisTests(ValidateTestCase):
    def test_unknown_label_is_rejected(self) -> None:
        body = body_with(hypothesis={"label": "ransomware", "confidence": "high"})
        self.assert_rejected_mentioning(body, "ransomware")

    def test_bad_confidence_is_rejected(self) -> None:
        body = body_with(hypothesis={"label": "unknown", "confidence": "certain"})
        self.assert_rejected_mentioning(body, "confidence")

    def test_all_three_confidence_values_are_accepted(self) -> None:
        for confidence in ("high", "medium", "low"):
            with self.subTest(confidence=confidence):
                body = body_with(hypothesis={"label": "unknown", "confidence": confidence})
                self.assertEqual(self.errors(body), [])


class AlternativesTests(ValidateTestCase):
    def test_empty_alternatives_are_rejected(self) -> None:
        self.assert_rejected_mentioning(body_with(alternatives=[]), "alternatives")

    def test_alternative_with_unknown_label_is_rejected(self) -> None:
        body = body_with(alternatives=[{"label": "aliens", "why": "x"}])
        self.assert_rejected_mentioning(body, "aliens")

    def test_alternative_without_why_is_rejected(self) -> None:
        body = body_with(alternatives=[{"label": "unknown"}])
        self.assert_rejected_mentioning(body, "why")

    def test_alternative_with_empty_why_is_rejected(self) -> None:
        body = body_with(alternatives=[{"label": "unknown", "why": "  "}])
        self.assert_rejected_mentioning(body, "why")

    def test_alternative_with_empty_label_is_rejected(self) -> None:
        body = body_with(alternatives=[{"label": "", "why": "x"}])
        self.assert_rejected_mentioning(body, "label")

    def test_alternative_that_is_not_a_dict_is_rejected(self) -> None:
        self.assert_rejected_mentioning(body_with(alternatives=["unknown"]), "alternatives[0]")

    def test_one_bad_alternative_among_good_ones_is_rejected(self) -> None:
        good = {"label": "unknown", "why": "x"}
        body = body_with(alternatives=[good, {"label": "aliens", "why": "x"}])
        self.assert_rejected_mentioning(body, "alternatives[1]")


class EvidenceTests(ValidateTestCase):
    def test_empty_evidence_is_rejected(self) -> None:
        self.assert_rejected_mentioning(body_with(evidence_event_ids=[]), "evidence_event_ids")

    def test_evidence_id_from_another_incident_is_rejected(self) -> None:
        body = body_with(evidence_event_ids=["evt_s1000001", "evt_s2000001"])
        self.assert_rejected_mentioning(body, "evt_s2000001")

    def test_invented_evidence_id_is_rejected(self) -> None:
        self.assert_rejected_mentioning(body_with(evidence_event_ids=["evt_deadbeef"]), "evt_deadbeef")

    def test_evidence_is_checked_against_the_given_incident_events(self) -> None:
        body = body_with(evidence_event_ids=["evt_s2000001"])
        self.assertEqual(validate(body, {"evt_s2000001"}), [])


class ManyProblemsTests(ValidateTestCase):
    def test_every_problem_is_reported(self) -> None:
        body = body_with(summary=1, alternatives=[], evidence_event_ids=["evt_nope"])
        self.assertGreaterEqual(len(self.errors(body)), 3)


if __name__ == "__main__":
    unittest.main()

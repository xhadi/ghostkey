"""Tests for core/scoring.py (pure functions, no DB)."""
from __future__ import annotations

import unittest

from core import scoring


def bait_event(stage: str = "source", action: str = "list_repos") -> dict:
    return {"token_kind": "bait", "bait_id": "BAIT-X", "stage": stage, "action": action}


def incident_with_stages(stages: list[str]) -> dict:
    return {"stages": stages}


class SeverityTests(unittest.TestCase):
    def test_boundaries(self) -> None:
        cases = [
            (0, "low"), (39, "low"),
            (40, "medium"), (69, "medium"),
            (70, "high"), (89, "high"),
            (90, "critical"), (95, "critical"), (200, "critical"),
        ]
        for score, expected in cases:
            with self.subTest(score=score):
                self.assertEqual(scoring.severity(score), expected)


class OrderStagesTests(unittest.TestCase):
    def test_orders_source_build_publish(self) -> None:
        self.assertEqual(scoring.order_stages(["publish", "source", "build"]),
                         ["source", "build", "publish"])

    def test_removes_duplicates_and_unknown(self) -> None:
        self.assertEqual(scoring.order_stages(["build", "unknown", "build", "source"]),
                         ["source", "build"])

    def test_empty(self) -> None:
        self.assertEqual(scoring.order_stages([]), [])


class BaitHitsTests(unittest.TestCase):
    def rules(self, hits: list[dict]) -> list[str]:
        return [h["rule"] for h in hits]

    def test_new_incident_gets_only_bait_use(self) -> None:
        hits = scoring.bait_hits(bait_event(), None)
        self.assertEqual(hits, [{"rule": "bait_use", "points": 60}])

    def test_second_stage_when_stage_is_new_to_incident(self) -> None:
        hits = scoring.bait_hits(bait_event(stage="build"), incident_with_stages(["source"]))
        self.assertEqual(self.rules(hits), ["bait_use", "second_stage_bait"])
        self.assertEqual(hits[1]["points"], 20)

    def test_no_second_stage_when_stage_already_seen(self) -> None:
        hits = scoring.bait_hits(bait_event(stage="source"), incident_with_stages(["source"]))
        self.assertEqual(self.rules(hits), ["bait_use"])

    def test_no_second_stage_for_unknown_stage(self) -> None:
        hits = scoring.bait_hits(bait_event(stage="unknown"), incident_with_stages(["source"]))
        self.assertEqual(self.rules(hits), ["bait_use"])

    def test_write_or_publish_actions(self) -> None:
        for action in ("push", "publish", "api_write"):
            with self.subTest(action=action):
                hits = scoring.bait_hits(bait_event(action=action), None)
                self.assertEqual(self.rules(hits), ["bait_use", "bait_write_or_publish"])
                self.assertEqual(hits[1]["points"], 15)

    def test_read_actions_are_not_write(self) -> None:
        for action in ("list_repos", "clone", "login", "install", "api_read", "other"):
            with self.subTest(action=action):
                hits = scoring.bait_hits(bait_event(action=action), None)
                self.assertEqual(self.rules(hits), ["bait_use"])


if __name__ == "__main__":
    unittest.main()

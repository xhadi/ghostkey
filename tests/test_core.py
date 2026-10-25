"""Tests for core/engine.py: correlation, scoring and actions. Each test uses its own temp DB."""
from __future__ import annotations

import json
import sqlite3
import tempfile
import unittest
from datetime import timedelta
from pathlib import Path

from common import db
from core.engine import process_pending
from fixtures.load_fixtures import read_events
from tests.fake_rules import fake_behavior_hits

EXPECTED_STATE = json.loads(
    (Path(__file__).resolve().parent.parent / "fixtures" / "expected_state.json").read_text(encoding="utf-8")
)


def expected_incident(incident_id: str) -> dict:
    return next(i for i in EXPECTED_STATE["incidents"] if i["incident_id"] == incident_id)


class CoreTestCase(unittest.TestCase):
    """Gives each test a fresh temp DB and small helpers to load events and read state."""

    def setUp(self) -> None:
        tmp = tempfile.TemporaryDirectory(ignore_cleanup_errors=True)
        self.addCleanup(tmp.cleanup)
        self.conn = db.connect(Path(tmp.name) / "test.db")
        self.addCleanup(self.conn.close)  # runs before tmp.cleanup (cleanups run last-in first-out)
        db.init(self.conn)
        self.baselines = db.load_json("baselines.json")

    def load_fixtures(self, *names: str) -> None:
        for event in read_events(list(names)):
            db.insert_event(self.conn, event)
        self.conn.commit()

    def run_core(self) -> int:
        return process_pending(self.conn, fake_behavior_hits, self.baselines)

    def incidents(self) -> list[dict]:
        rows = self.conn.execute("SELECT * FROM incidents ORDER BY incident_id").fetchall()
        result = []
        for row in rows:
            inc = dict(row)
            for key in ("source_ips", "token_ids", "stages", "rules_hit"):
                inc[key] = json.loads(inc[key])
            result.append(inc)
        return result

    def signals(self, incident_id: str | None = None) -> list[dict]:
        sql = "SELECT * FROM signals ORDER BY signal_id"
        rows = self.conn.execute(sql).fetchall()
        return [dict(r) for r in rows if incident_id is None or r["incident_id"] == incident_id]

    def actions(self, incident_id: str) -> list[tuple]:
        rows = self.conn.execute(
            "SELECT kind, target, tier, status FROM actions WHERE incident_id = ? ORDER BY action_id",
            (incident_id,),
        ).fetchall()
        return [tuple(r) for r in rows]

    def event_ids_of(self, incident_id: str) -> list[str]:
        rows = self.conn.execute(
            "SELECT event_id FROM events WHERE incident_id = ? ORDER BY ts, event_id", (incident_id,)
        ).fetchall()
        return [r["event_id"] for r in rows]

    def add_events(self, *events: dict) -> None:
        for event in events:
            db.insert_event(self.conn, event)
        self.conn.commit()


BASE_TIME = "2026-10-25T10:00:00Z"


def at(minutes: int, seconds: int = 0) -> str:
    """A timestamp `minutes` after 10:00:00Z (keeps test times easy to read)."""
    base = db.parse_iso(BASE_TIME)
    return (base + timedelta(minutes=minutes, seconds=seconds)).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_event(event_id: str, ts: str, **overrides) -> dict:
    """A valid event dict; pass only the fields a test cares about."""
    event = {
        "event_id": event_id, "ts": ts, "session_id": "s_test", "source_ip": "10.0.0.1",
        "user_agent": "test", "token_kind": "none", "bait_id": None, "credential_id": None,
        "stage": "unknown", "service": "git", "method": "GET", "path": "/x", "action": "other",
        "target": None, "status_code": 200, "result": "ok", "routed_to": "real",
        "incident_id": None, "processed": 0,
    }
    event.update(overrides)
    return event


def bait_event(event_id: str, ts: str, bait_id: str = "BAIT-A", **overrides) -> dict:
    fields = {"token_kind": "bait", "bait_id": bait_id, "stage": "source", "routed_to": "decoy"}
    fields.update(overrides)
    return make_event(event_id, ts, **fields)


def real_event(event_id: str, ts: str, **overrides) -> dict:
    """A REAL-CI-01 npm event. Defaults are normal traffic (allowed IP, install, allowed target)."""
    fields = {
        "token_kind": "real", "credential_id": "REAL-CI-01", "source_ip": "172.30.0.10",
        "stage": "build", "service": "npm", "action": "install", "target": "@kfu/build-utils",
    }
    fields.update(overrides)
    return make_event(event_id, ts, **fields)


class Scenario1Tests(CoreTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.load_fixtures("scenario1")
        self.processed = self.run_core()

    def test_processes_all_five_events(self) -> None:
        self.assertEqual(self.processed, 5)
        unprocessed = self.conn.execute("SELECT COUNT(*) FROM events WHERE processed = 0").fetchone()[0]
        self.assertEqual(unprocessed, 0)

    def test_one_bait_incident_matches_expected_state(self) -> None:
        incidents = self.incidents()
        self.assertEqual(len(incidents), 1)
        inc, want = incidents[0], expected_incident("INC-001")
        for key in ("incident_id", "signal_kind", "confidence", "score", "severity", "status",
                    "source_ips", "token_ids", "stages", "rules_hit"):
            with self.subTest(field=key):
                self.assertEqual(inc[key], want[key])

    def test_all_events_attached_and_timestamps_set(self) -> None:
        self.assertEqual(self.event_ids_of("INC-001"), expected_incident("INC-001")["events"])
        inc = self.incidents()[0]
        self.assertEqual(inc["created_ts"], "2026-10-25T10:00:00Z")
        self.assertEqual(inc["updated_ts"], "2026-10-25T10:03:30Z")

    def test_three_signals_with_token_ids(self) -> None:
        signals = self.signals("INC-001")
        self.assertEqual(len(signals), 3)
        self.assertEqual([s["token_id"] for s in signals], ["BAIT-SRC-01", "BAIT-CI-02", "BAIT-CI-02"])
        self.assertEqual([(s["rule"], s["points"], s["event_id"]) for s in signals],
                         [(h["rule"], h["points"], h["event_id"]) for h in expected_incident("INC-001")["rules_hit"]])

    def test_actions_are_notify_and_disable_each_bait(self) -> None:
        self.assertEqual(self.actions("INC-001"), [
            ("notify", "security-team", "auto", "done"),
            ("disable_bait", "BAIT-SRC-01", "auto", "done"),
            ("disable_bait", "BAIT-CI-02", "auto", "done"),
        ])


class Scenario2Tests(CoreTestCase):
    def setUp(self) -> None:
        super().setUp()
        self.load_fixtures("scenario2")
        self.processed = self.run_core()

    def test_one_behavior_incident_matches_expected_state(self) -> None:
        incidents = self.incidents()
        self.assertEqual(len(incidents), 1)
        inc, want = incidents[0], expected_incident("INC-002")
        for key in ("signal_kind", "confidence", "score", "severity", "status",
                    "source_ips", "token_ids", "stages", "rules_hit"):
            with self.subTest(field=key):
                self.assertEqual(inc[key], want[key])
        self.assertEqual(inc["incident_id"], "INC-001")  # alone, it is the first incident

    def test_all_three_events_attached(self) -> None:
        self.assertEqual(self.processed, 3)
        self.assertEqual(self.event_ids_of("INC-001"), expected_incident("INC-002")["events"])
        inc = self.incidents()[0]
        self.assertEqual(inc["created_ts"], "2026-10-25T10:10:00Z")
        self.assertEqual(inc["updated_ts"], "2026-10-25T10:11:05Z")

    def test_exactly_three_signals_all_attached(self) -> None:
        signals = self.signals()
        self.assertEqual(len(signals), 3)  # the repeated new_source / out_of_scope hits are not stored
        self.assertTrue(all(s["incident_id"] == "INC-001" for s in signals))
        self.assertTrue(all(s["token_id"] == "REAL-CI-01" for s in signals))

    def test_actions_are_notify_and_pending_revoke(self) -> None:
        self.assertEqual(self.actions("INC-001"), [
            ("notify", "security-team", "auto", "done"),
            ("revoke_credential", "REAL-CI-01", "approval", "pending"),
        ])


class ScopedRevokeTests(CoreTestCase):
    """Revoke prompts are per (credential, source IP); zero-hit real events never join by credential."""

    def setUp(self) -> None:
        super().setUp()
        self.load_fixtures("scenario2")
        self.run_core()

    def revokes(self, incident_id: str) -> list[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM actions WHERE incident_id = ? AND kind = 'revoke_credential' ORDER BY action_id",
            (incident_id,),
        ).fetchall()

    def test_revoke_prompt_is_scoped_to_attacker_ip(self) -> None:
        revokes = self.revokes("INC-001")
        self.assertEqual(len(revokes), 1)
        self.assertEqual(revokes[0]["scope_ip"], "172.30.0.77")
        self.assertEqual(revokes[0]["target"], "REAL-CI-01")
        self.assertEqual([a[0] for a in self.actions("INC-001")], ["notify", "revoke_credential"])

    def test_zero_hit_real_event_does_not_join_by_credential(self) -> None:
        normal = next(e for e in read_events(["normal"]) if e["event_id"] == "evt_n0000001")
        normal.update(event_id="evt_n_after", ts="2026-10-25T10:12:05Z", incident_id=None, processed=0)
        self.add_events(normal)
        self.run_core()
        row = self.conn.execute("SELECT incident_id FROM events WHERE event_id = 'evt_n_after'").fetchone()
        self.assertIsNone(row["incident_id"])
        self.assertEqual(len(self.event_ids_of("INC-001")), 3)
        self.assertEqual(self.incidents()[0]["score"], 80)

    def test_new_ip_with_hits_joins_and_asks_again(self) -> None:
        self.add_events(real_event("evt_ip99", at(13), source_ip="172.30.0.99"))
        self.run_core()
        self.assertEqual(len(self.incidents()), 1)
        self.assertEqual(self.event_ids_of("INC-001")[-1], "evt_ip99")
        revokes = self.revokes("INC-001")
        self.assertEqual({r["scope_ip"] for r in revokes}, {"172.30.0.77", "172.30.0.99"})
        self.assertTrue(all(r["status"] == "pending" and r["tier"] == "approval" for r in revokes))
        self.assertEqual(self.incidents()[0]["score"], 80)

    def test_repeat_from_same_ip_adds_no_second_prompt(self) -> None:
        self.add_events(real_event("evt_ip77", at(13), source_ip="172.30.0.77"))
        self.run_core()
        self.assertEqual(self.event_ids_of("INC-001")[-1], "evt_ip77")
        self.assertEqual(len(self.revokes("INC-001")), 1)


class NormalTrafficTests(CoreTestCase):
    def test_normal_traffic_makes_no_signals_and_no_incidents(self) -> None:
        self.load_fixtures("normal")
        self.assertEqual(self.run_core(), 2)
        self.assertEqual(self.incidents(), [])
        self.assertEqual(self.signals(), [])
        rows = self.conn.execute("SELECT processed, incident_id FROM events").fetchall()
        self.assertEqual([(r["processed"], r["incident_id"]) for r in rows], [(1, None), (1, None)])


class AllFixturesTests(CoreTestCase):
    def test_two_incidents_in_order_and_normal_events_stay_unattached(self) -> None:
        self.load_fixtures("normal", "scenario1", "scenario2")
        self.assertEqual(self.run_core(), 10)
        incidents = self.incidents()
        self.assertEqual([i["incident_id"] for i in incidents], ["INC-001", "INC-002"])
        for inc, want_id in zip(incidents, ("INC-001", "INC-002")):
            want = expected_incident(want_id)
            for key in ("signal_kind", "confidence", "score", "severity", "status",
                        "source_ips", "token_ids", "stages", "rules_hit"):
                with self.subTest(incident=want_id, field=key):
                    self.assertEqual(inc[key], want[key])
            self.assertEqual(self.event_ids_of(want_id), want["events"])
        self.assertEqual(self.actions("INC-001")[1:], [
            ("disable_bait", "BAIT-SRC-01", "auto", "done"),
            ("disable_bait", "BAIT-CI-02", "auto", "done"),
        ])
        self.assertEqual(self.actions("INC-002")[1], ("revoke_credential", "REAL-CI-01", "approval", "pending"))
        normal = self.conn.execute(
            "SELECT incident_id FROM events WHERE event_id LIKE 'evt_n%'").fetchall()
        self.assertEqual([r["incident_id"] for r in normal], [None, None])
        self.assertEqual(len(self.signals()), 6)


class BehaviorCountingTests(CoreTestCase):
    def test_hits_below_threshold_store_signals_without_incident(self) -> None:
        self.add_events(real_event("evt_1", at(0), source_ip="172.30.0.77"))  # new_source 20
        self.run_core()
        self.assertEqual(self.incidents(), [])
        signals = self.signals()
        self.assertEqual([(s["rule"], s["incident_id"]) for s in signals], [("new_source", None)])
        event = self.conn.execute("SELECT incident_id, processed FROM events").fetchone()
        self.assertEqual((event["incident_id"], event["processed"]), (None, 1))
        self.assertEqual(self.conn.execute("SELECT COUNT(*) FROM actions").fetchone()[0], 0)

    def test_repeated_rule_in_window_is_not_stored_twice(self) -> None:
        self.add_events(
            real_event("evt_1", at(0), source_ip="172.30.0.77"),
            real_event("evt_2", at(1), source_ip="172.30.0.77"),
        )
        self.run_core()
        self.assertEqual(len(self.signals()), 1)
        self.assertEqual(self.incidents(), [])

    def test_events_in_the_same_second_are_processed_in_arrival_order(self) -> None:
        # event_id is random hex, so "evt_z" arriving first must still win over "evt_a".
        self.add_events(
            real_event("evt_z", at(0), source_ip="172.30.0.77"),
            real_event("evt_a", at(0), source_ip="172.30.0.77"),
        )
        self.run_core()
        self.assertEqual([s["event_id"] for s in self.signals()], ["evt_z"])

    def test_opens_at_exactly_60_points(self) -> None:
        # From the allowed IP: out_of_scope 25 first, then publish gives unexpected_publish 35.
        self.add_events(
            real_event("evt_1", at(0), target="@kfu/payments-sdk"),
            real_event("evt_2", at(1), action="publish", stage="publish"),
        )
        self.run_core()
        incidents = self.incidents()
        self.assertEqual(len(incidents), 1)
        self.assertEqual((incidents[0]["score"], incidents[0]["severity"]), (60, "medium"))
        self.assertEqual(self.event_ids_of("INC-001"), ["evt_1", "evt_2"])

    def test_below_threshold_with_two_rules_does_not_open(self) -> None:
        # new_source 20 + out_of_scope 25 = 45 (< 60) even though two events happened.
        self.add_events(
            real_event("evt_1", at(0), source_ip="172.30.0.77"),
            real_event("evt_2", at(1), source_ip="172.30.0.77", target="@kfu/payments-sdk"),
        )
        self.run_core()
        self.assertEqual(self.incidents(), [])
        self.assertEqual(len(self.signals()), 2)

    def test_hits_older_than_30_minutes_do_not_count(self) -> None:
        self.add_events(
            real_event("evt_1", at(0), source_ip="172.30.0.77"),  # new_source 20, then it expires
            real_event("evt_2", at(31), source_ip="172.30.0.77", action="publish", stage="publish"),
        )
        self.run_core()
        incidents = self.incidents()
        self.assertEqual(len(incidents), 1)
        # evt_2 alone is 20 + 25 + 35 = 80; the expired evt_1 hit is not attached.
        self.assertEqual(incidents[0]["score"], 80)
        self.assertEqual(self.event_ids_of("INC-001"), ["evt_2"])
        old = self.conn.execute("SELECT incident_id FROM events WHERE event_id = 'evt_1'").fetchone()
        self.assertIsNone(old["incident_id"])
        orphan = [s for s in self.signals() if s["event_id"] == "evt_1"]
        self.assertEqual([s["incident_id"] for s in orphan], [None])

    def test_other_credentials_do_not_share_points(self) -> None:
        self.add_events(
            real_event("evt_1", at(0), source_ip="172.30.0.77"),
            real_event("evt_2", at(1), source_ip="172.30.0.77", credential_id="REAL-OTHER-01",
                       action="publish", stage="publish"),
        )
        self.run_core()  # REAL-OTHER-01 has no baseline, so it never scores
        self.assertEqual(self.incidents(), [])
        self.assertEqual(len(self.signals()), 1)

    def test_later_zero_hit_event_of_same_credential_stays_out_of_the_incident(self) -> None:
        self.load_fixtures("scenario2")
        self.run_core()
        self.add_events(real_event("evt_late", at(30), source_ip="172.30.0.10"))
        self.run_core()
        self.assertEqual(len(self.incidents()), 1)
        self.assertEqual(self.event_ids_of("INC-001")[-1], "evt_s2000003")
        self.assertEqual(len(self.signals()), 3)
        self.assertEqual(self.incidents()[0]["source_ips"], ["172.30.0.77"])


class CorrelationTests(CoreTestCase):
    def test_same_ip_after_more_than_30_minutes_opens_new_incident(self) -> None:
        self.add_events(
            bait_event("evt_1", at(0), bait_id="BAIT-A"),
            bait_event("evt_2", at(31), bait_id="BAIT-B"),  # 31 minutes after the last event
        )
        self.run_core()
        self.assertEqual([i["incident_id"] for i in self.incidents()], ["INC-001", "INC-002"])
        self.assertEqual(self.incidents()[1]["token_ids"], ["BAIT-B"])

    def test_same_ip_at_exactly_30_minutes_joins(self) -> None:
        self.add_events(
            bait_event("evt_1", at(0), bait_id="BAIT-A"),
            bait_event("evt_2", at(30), bait_id="BAIT-B"),
        )
        self.run_core()
        incidents = self.incidents()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["token_ids"], ["BAIT-A", "BAIT-B"])

    def test_window_is_measured_from_last_event_not_from_incident_start(self) -> None:
        self.add_events(
            bait_event("evt_1", at(0), bait_id="BAIT-A"),
            bait_event("evt_2", at(25), bait_id="BAIT-A"),
            bait_event("evt_3", at(50), bait_id="BAIT-B"),  # 25 minutes after evt_2
        )
        self.run_core()
        self.assertEqual(len(self.incidents()), 1)

    def test_same_bait_joins_even_from_a_new_ip_and_much_later(self) -> None:
        self.add_events(
            bait_event("evt_1", at(0), bait_id="BAIT-A", source_ip="10.0.0.1"),
            bait_event("evt_2", at(120), bait_id="BAIT-A", source_ip="10.0.0.2"),
        )
        self.run_core()
        incidents = self.incidents()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(incidents[0]["source_ips"], ["10.0.0.1", "10.0.0.2"])

    def test_event_without_token_joins_by_ip_and_adds_no_hits(self) -> None:
        self.add_events(
            bait_event("evt_1", at(0)),
            make_event("evt_2", at(10), token_kind="none"),
        )
        self.run_core()
        incidents = self.incidents()
        self.assertEqual(len(incidents), 1)
        self.assertEqual(self.event_ids_of("INC-001"), ["evt_1", "evt_2"])
        self.assertEqual(incidents[0]["updated_ts"], at(10))
        self.assertEqual(incidents[0]["score"], 60)
        self.assertEqual(len(self.signals()), 1)
        self.assertEqual(len(self.actions("INC-001")), 2)  # notify + disable_bait, nothing new

    def test_unknown_token_from_attacker_ip_joins_but_other_ip_does_not(self) -> None:
        self.add_events(
            bait_event("evt_1", at(0), source_ip="10.0.0.1"),
            make_event("evt_2", at(5), token_kind="unknown", source_ip="10.0.0.1"),
            make_event("evt_3", at(6), token_kind="unknown", source_ip="10.0.0.99"),
        )
        self.run_core()
        self.assertEqual(self.event_ids_of("INC-001"), ["evt_1", "evt_2"])
        stray = self.conn.execute("SELECT incident_id, processed FROM events WHERE event_id = 'evt_3'").fetchone()
        self.assertEqual((stray["incident_id"], stray["processed"]), (None, 1))

    def test_closed_incident_is_never_joined(self) -> None:
        self.add_events(bait_event("evt_1", at(0)))
        self.run_core()
        self.conn.execute("UPDATE incidents SET status = 'closed' WHERE incident_id = 'INC-001'")
        self.conn.commit()
        self.add_events(bait_event("evt_2", at(1)))  # same bait, same IP, one minute later
        self.run_core()
        self.assertEqual([i["incident_id"] for i in self.incidents()], ["INC-001", "INC-002"])
        self.assertEqual(self.incidents()[0]["status"], "closed")
        self.assertEqual(self.event_ids_of("INC-001"), ["evt_1"])
        self.assertEqual(self.event_ids_of("INC-002"), ["evt_2"])

    def test_latest_updated_incident_wins_when_several_match(self) -> None:
        self.add_events(
            bait_event("evt_1", at(0), bait_id="BAIT-A", source_ip="10.0.0.1"),
            bait_event("evt_2", at(5), bait_id="BAIT-B", source_ip="10.0.0.2"),
            # BAIT-A matches INC-001 by token, 10.0.0.2 matches INC-002 by IP.
            bait_event("evt_3", at(10), bait_id="BAIT-A", source_ip="10.0.0.2"),
        )
        self.run_core()
        self.assertEqual(self.event_ids_of("INC-001"), ["evt_1"])
        self.assertEqual(self.event_ids_of("INC-002"), ["evt_2", "evt_3"])

    def test_stages_are_ordered_and_unknown_is_left_out(self) -> None:
        self.add_events(
            bait_event("evt_1", at(0), stage="publish", action="publish"),
            bait_event("evt_2", at(1), stage="unknown"),
            bait_event("evt_3", at(2), stage="source"),
        )
        self.run_core()
        self.assertEqual(self.incidents()[0]["stages"], ["source", "publish"])

    def test_second_stage_bait_needs_a_new_stage(self) -> None:
        self.add_events(
            bait_event("evt_1", at(0), stage="source"),
            bait_event("evt_2", at(1), stage="source"),
            bait_event("evt_3", at(2), stage="build"),
        )
        self.run_core()
        rules = [(h["rule"], h["event_id"]) for h in self.incidents()[0]["rules_hit"]]
        self.assertEqual(rules, [("bait_use", "evt_1"), ("second_stage_bait", "evt_3")])

    def test_bait_joining_a_behavior_incident_upgrades_it(self) -> None:
        self.load_fixtures("scenario2")
        self.run_core()
        self.add_events(bait_event("evt_bait", at(15), bait_id="BAIT-A", source_ip="172.30.0.77"))
        self.run_core()
        inc = self.incidents()[0]
        self.assertEqual((inc["signal_kind"], inc["confidence"], inc["status"]),
                         ("behavior", "high", "open"))
        self.assertEqual(inc["token_ids"], ["REAL-CI-01", "BAIT-A"])
        rules = [h["rule"] for h in inc["rules_hit"]]
        self.assertEqual(rules[-2:], ["bait_use", "second_stage_bait"])
        self.assertIn(("disable_bait", "BAIT-A", "auto", "done"), self.actions("INC-001"))
        self.assertEqual(len([a for a in self.actions("INC-001") if a[0] == "notify"]), 1)


class ProcessPendingTests(CoreTestCase):
    def test_second_call_processes_nothing_and_changes_nothing(self) -> None:
        self.load_fixtures("normal", "scenario1", "scenario2")
        self.assertEqual(self.run_core(), 10)
        counts_before = [self.conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                         for t in ("incidents", "signals", "actions")]
        incidents_before = self.incidents()
        self.assertEqual(self.run_core(), 0)
        counts_after = [self.conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]
                        for t in ("incidents", "signals", "actions")]
        self.assertEqual(counts_before, counts_after)
        self.assertEqual(incidents_before, self.incidents())

    def test_events_are_processed_in_time_order_not_id_order(self) -> None:
        self.add_events(
            bait_event("evt_a", at(5), bait_id="BAIT-B", stage="build"),   # later, but sorts first by id
            bait_event("evt_b", at(0), bait_id="BAIT-A", stage="source"),
        )
        self.run_core()
        rules = [(h["rule"], h["event_id"]) for h in self.incidents()[0]["rules_hit"]]
        self.assertEqual(rules, [("bait_use", "evt_b"), ("second_stage_bait", "evt_a")])

    def test_empty_database_processes_zero(self) -> None:
        self.assertEqual(self.run_core(), 0)

    def test_event_that_crashes_core_is_skipped_and_later_events_still_run(self) -> None:
        self.add_events(
            bait_event("evt_1", at(0)),
            real_event("evt_2", at(1)),
            bait_event("evt_3", at(2), bait_id="BAIT-B", source_ip="10.0.0.99"),
        )

        def broken_rules(event: dict, baseline: dict | None) -> list[dict]:
            # The first hit is stored, then the second one (no "points") crashes core mid-event.
            return [{"rule": "new_source", "points": 20}, {"rule": "out_of_scope"}]

        self.assertEqual(process_pending(self.conn, broken_rules, self.baselines), 3)
        flags = self.conn.execute("SELECT event_id, processed, incident_id FROM events ORDER BY ts").fetchall()
        self.assertEqual([tuple(r) for r in flags],
                         [("evt_1", 1, "INC-001"), ("evt_2", 1, None), ("evt_3", 1, "INC-002")])
        self.assertEqual([s["event_id"] for s in self.signals()], ["evt_1", "evt_3"])  # evt_2 left nothing

    def test_rules_that_raise_count_as_no_hits_and_event_still_correlates(self) -> None:
        self.add_events(
            bait_event("evt_1", at(0), source_ip="172.30.0.66"),
            real_event("evt_2", at(1), source_ip="172.30.0.66"),
        )

        def raising_rules(event: dict, baseline: dict | None) -> list[dict]:
            raise RuntimeError("bug in brain.rules")

        self.assertEqual(process_pending(self.conn, raising_rules, self.baselines), 2)
        self.assertEqual(self.event_ids_of("INC-001"), ["evt_1", "evt_2"])
        self.assertEqual([s["event_id"] for s in self.signals()], ["evt_1"])

    def test_database_error_is_rolled_back_raised_and_event_left_unprocessed(self) -> None:
        self.add_events(bait_event("evt_1", at(0)), bait_event("evt_2", at(1)))
        self.conn.execute(
            "CREATE TRIGGER fail_evt_2 BEFORE UPDATE OF processed ON events WHEN NEW.event_id = 'evt_2'"
            " BEGIN SELECT RAISE(ABORT, 'database is locked'); END"
        )
        self.conn.commit()

        with self.assertRaises(sqlite3.Error):
            self.run_core()
        flags = self.conn.execute("SELECT event_id, processed FROM events ORDER BY ts").fetchall()
        self.assertEqual([(r["event_id"], r["processed"]) for r in flags], [("evt_1", 1), ("evt_2", 0)])
        self.assertEqual(self.event_ids_of("INC-001"), ["evt_1"])  # evt_2's join was rolled back

if __name__ == "__main__":
    unittest.main()

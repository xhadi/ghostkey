"""Tests for brain/worker.py: finding incidents to analyze, storing analyses, the LLM hook."""
from __future__ import annotations

import contextlib
import io
import sqlite3
import sys
import unittest
from unittest import mock

from brain import worker
from brain.analyst_rules import rules_analysis
from brain.validate import validate
from tests.brain_support import BrainTestCase
from tests.test_core import real_event


class StopLoop(Exception):
    """Raised by a fake sleep to end run_loop in a test."""


def capture_output():
    """Context manager that hides what the code under test prints."""
    return contextlib.redirect_stdout(io.StringIO())


class WorkerTestCase(BrainTestCase):
    """Both fixture incidents exist (INC-001 bait with 5 events, INC-002 behavior with 3)."""

    def setUp(self) -> None:
        super().setUp()
        self.load_fixtures("normal", "scenario1", "scenario2")
        self.run_core()

    def analyze(self, llm_fn=None) -> tuple[int, str]:
        """Run analyze_pending and return (count, printed text)."""
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            count = worker.analyze_pending(self.conn, llm_fn)
        return count, output.getvalue()

    def valid_llm_body(self, incident_id: str) -> dict:
        """A valid body that differs from the rules body (the summary says it came from the LLM)."""
        body = rules_analysis(self.incident(incident_id), self.events_of(incident_id))
        body["summary"] = "ملخص من النموذج اللغوي"
        return body

    def table_rows(self, table: str) -> list[tuple]:
        return [tuple(row) for row in self.conn.execute(f"SELECT * FROM {table} ORDER BY 1, 2")]


class RulesOnlyTests(WorkerTestCase):
    def test_analyzes_both_incidents_and_returns_the_count(self) -> None:
        count, _ = self.analyze()
        self.assertEqual(count, 2)
        self.assertEqual(sorted(self.stored_analyses()), ["INC-001", "INC-002"])

    def test_stored_rows_are_valid_rules_analyses_of_the_current_event_count(self) -> None:
        self.analyze()
        for incident_id, event_count in (("INC-001", 5), ("INC-002", 3)):
            with self.subTest(incident=incident_id):
                row = self.stored_analyses()[incident_id]
                events = self.events_of(incident_id)
                self.assertEqual((row["source"], row["valid"], row["based_on_event_count"]),
                                 ("rules", 1, event_count))
                self.assertEqual(validate(row["body"], {e["event_id"] for e in events}), [])
                self.assertEqual(row["body"], rules_analysis(self.incident(incident_id), events))

    def test_row_has_a_utc_timestamp(self) -> None:
        self.analyze()
        ts = self.stored_analyses()["INC-001"]["ts"]
        self.assertRegex(ts, r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")

    def test_body_is_stored_as_readable_arabic_not_escapes(self) -> None:
        self.analyze()
        raw = self.conn.execute("SELECT body FROM analyses WHERE incident_id = 'INC-001'").fetchone()["body"]
        self.assertIn("جلسة", raw)
        self.assertNotIn("\\u", raw)

    def test_second_call_analyzes_nothing_and_leaves_rows_alone(self) -> None:
        self.analyze()
        before = self.table_rows("analyses")
        count, output = self.analyze()
        self.assertEqual(count, 0)
        self.assertEqual(output, "")
        self.assertEqual(self.table_rows("analyses"), before)

    def test_one_line_is_printed_per_analysis(self) -> None:
        _, output = self.analyze()
        self.assertEqual(output.splitlines(), [
            "brain: INC-001 analyzed source=rules label=package_publish",
            "brain: INC-002 analyzed source=rules label=package_publish",
        ])

    def test_only_the_analyses_table_is_written(self) -> None:
        tables = ("events", "incidents", "signals", "actions")
        before = {table: self.table_rows(table) for table in tables}
        self.analyze()
        self.assertEqual({table: self.table_rows(table) for table in tables}, before)

    def test_no_incidents_means_nothing_to_do(self) -> None:
        self.conn.execute("DELETE FROM actions")
        self.conn.execute("DELETE FROM signals")
        self.conn.execute("DELETE FROM incidents")
        self.conn.commit()
        self.assertEqual(self.analyze(), (0, ""))

    def test_incident_without_events_is_skipped_quietly(self) -> None:
        self.conn.execute("UPDATE events SET incident_id = NULL WHERE incident_id = 'INC-002'")
        self.conn.commit()
        count, _ = self.analyze()
        self.assertEqual(count, 1)
        self.assertNotIn("INC-002", self.stored_analyses())


class ReanalysisTests(WorkerTestCase):
    def add_event_to_inc_002(self) -> None:
        """A new REAL-CI-01 event from the attacker's IP: core attaches it to INC-002."""
        self.add_events(real_event("evt_extra001", "2026-10-25T10:12:00Z", source_ip="172.30.0.77"))
        self.run_core()
        self.assertEqual(len(self.events_of("INC-002")), 4)

    def test_new_event_triggers_reanalysis_of_that_incident_only(self) -> None:
        self.analyze()
        before_inc_001 = self.stored_analyses()["INC-001"]
        self.add_event_to_inc_002()
        count, _ = self.analyze()
        self.assertEqual(count, 1)
        rows = self.stored_analyses()
        self.assertEqual(rows["INC-002"]["based_on_event_count"], 4)
        self.assertIn("4 أحداث", rows["INC-002"]["body"]["limits"])
        self.assertEqual(rows["INC-001"], before_inc_001)

    def test_reanalysis_replaces_the_row_instead_of_adding_one(self) -> None:
        self.analyze()
        self.add_event_to_inc_002()
        self.analyze()
        count = self.conn.execute("SELECT COUNT(*) FROM analyses WHERE incident_id = 'INC-002'").fetchone()[0]
        self.assertEqual(count, 1)

    def test_after_reanalysis_the_next_call_has_nothing_to_do(self) -> None:
        self.analyze()
        self.add_event_to_inc_002()
        self.analyze()
        self.assertEqual(self.analyze()[0], 0)


class LlmHookTests(WorkerTestCase):
    def test_valid_llm_body_is_stored_with_source_llm(self) -> None:
        bodies = {i: self.valid_llm_body(i) for i in ("INC-001", "INC-002")}
        calls = []

        def llm_fn(incident: dict, events: list[dict]) -> dict:
            calls.append((incident["incident_id"], [e["event_id"] for e in events]))
            return bodies[incident["incident_id"]]

        count, output = self.analyze(llm_fn)
        self.assertEqual(count, 2)
        rows = self.stored_analyses()
        for incident_id in ("INC-001", "INC-002"):
            with self.subTest(incident=incident_id):
                self.assertEqual((rows[incident_id]["source"], rows[incident_id]["valid"]), ("llm", 1))
                self.assertEqual(rows[incident_id]["body"], bodies[incident_id])
        self.assertIn("brain: INC-001 analyzed source=llm label=package_publish", output)

    def test_rules_analysis_is_stored_before_the_llm_is_asked(self) -> None:
        # A real LLM call can take a minute; the dashboard must not wait for it.
        seen_while_waiting = {}

        def llm_fn(incident: dict, events: list[dict]) -> dict:
            incident_id = incident["incident_id"]
            seen_while_waiting[incident_id] = self.stored_analyses().get(incident_id, {}).get("source")
            return self.valid_llm_body(incident_id)

        self.analyze(llm_fn)
        self.assertEqual(seen_while_waiting, {"INC-001": "rules", "INC-002": "rules"})
        self.assertEqual({i: row["source"] for i, row in self.stored_analyses().items()},
                         {"INC-001": "llm", "INC-002": "llm"})

    def test_llm_receives_the_decoded_incident_and_only_its_own_events(self) -> None:
        calls = []

        def llm_fn(incident: dict, events: list[dict]) -> None:
            calls.append((incident, events))

        self.analyze(llm_fn)
        incident, events = calls[0]
        self.assertEqual(incident["incident_id"], "INC-001")
        self.assertEqual(incident["token_ids"], ["BAIT-SRC-01", "BAIT-CI-02"])
        self.assertEqual([e["event_id"] for e in events], self.event_ids_of("INC-001"))

    def test_invalid_llm_body_falls_back_to_rules_and_logs_the_errors(self) -> None:
        def llm_fn(incident: dict, events: list[dict]) -> dict | None:
            if incident["incident_id"] != "INC-001":
                return None
            body = rules_analysis(incident, events)
            body["evidence_event_ids"] = ["evt_s2000001"]  # an event of the OTHER incident
            return body

        count, output = self.analyze(llm_fn)
        self.assertEqual(count, 2)
        row = self.stored_analyses()["INC-001"]
        self.assertEqual((row["source"], row["valid"]), ("rules", 1))
        self.assertEqual(row["body"], rules_analysis(self.incident("INC-001"), self.events_of("INC-001")))
        self.assertIn("rejected", output)
        self.assertIn("evt_s2000001", output)

    def test_llm_returning_none_falls_back_to_rules(self) -> None:
        self.analyze(lambda incident, events: None)
        self.assertEqual({r["source"] for r in self.stored_analyses().values()}, {"rules"})

    def test_llm_returning_something_that_is_not_a_dict_falls_back_to_rules(self) -> None:
        self.analyze(lambda incident, events: "not a dict")
        self.assertEqual({r["source"] for r in self.stored_analyses().values()}, {"rules"})

    def test_llm_raising_falls_back_to_rules_and_the_loop_goes_on(self) -> None:
        body_2 = self.valid_llm_body("INC-002")

        def llm_fn(incident: dict, events: list[dict]) -> dict:
            if incident["incident_id"] == "INC-001":
                raise RuntimeError("model is down")
            return body_2

        count, output = self.analyze(llm_fn)
        self.assertEqual(count, 2)
        rows = self.stored_analyses()
        self.assertEqual((rows["INC-001"]["source"], rows["INC-001"]["valid"]), ("rules", 1))
        self.assertEqual((rows["INC-002"]["source"], rows["INC-002"]["valid"]), ("llm", 1))
        self.assertIn("model is down", output)

    def test_without_an_llm_function_nothing_is_called(self) -> None:
        with mock.patch.object(worker, "call_llm") as call_llm:
            self.analyze(None)
        call_llm.assert_not_called()

    def test_llm_cannot_change_the_incident_it_was_given_into_the_stored_rules_body(self) -> None:
        def llm_fn(incident: dict, events: list[dict]) -> None:
            incident["signal_kind"] = "behavior"  # misbehaving hook
            events.clear()

        self.analyze(llm_fn)
        row = self.stored_analyses()["INC-001"]
        self.assertEqual(row["based_on_event_count"], 5)
        self.assertEqual(row["body"]["observed"], ["list_repos", "clone", "login", "publish"])
        self.assertEqual(row["body"]["hypothesis"]["confidence"], "medium")


class BugHandlingTests(WorkerTestCase):
    def test_invalid_rules_body_is_logged_loudly_and_stored_with_valid_zero(self) -> None:
        def broken(incident: dict, events: list[dict]) -> dict:
            body = rules_analysis(incident, events)
            body["alternatives"] = []
            return body

        with mock.patch.object(worker, "rules_analysis", broken):
            count, output = self.analyze()
        self.assertEqual(count, 2)
        row = self.stored_analyses()["INC-001"]
        self.assertEqual((row["source"], row["valid"]), ("rules", 0))
        self.assertIn("BUG", output)
        self.assertIn("alternatives", output)

    def test_valid_llm_body_is_still_stored_as_valid_when_the_rules_body_is_broken(self) -> None:
        body = self.valid_llm_body("INC-001")

        def broken(incident: dict, events: list[dict]) -> dict:
            return {}

        with mock.patch.object(worker, "rules_analysis", broken):
            self.analyze(lambda incident, events: body if incident["incident_id"] == "INC-001" else None)
        row = self.stored_analyses()["INC-001"]
        self.assertEqual((row["source"], row["valid"]), ("llm", 1))

    def test_crash_in_rules_analysis_skips_that_incident_and_goes_on(self) -> None:
        def crashing(incident: dict, events: list[dict]) -> dict:
            if incident["incident_id"] == "INC-001":
                raise KeyError("boom")
            return rules_analysis(incident, events)

        with mock.patch.object(worker, "rules_analysis", crashing):
            count, output = self.analyze()
        self.assertEqual(count, 1)
        self.assertEqual(sorted(self.stored_analyses()), ["INC-002"])
        self.assertIn("INC-001", output)
        self.assertIn("ERROR", output)

    def test_database_errors_are_not_swallowed(self) -> None:
        with mock.patch.object(worker, "store_analysis", side_effect=sqlite3.OperationalError("locked")):
            with capture_output():
                with self.assertRaises(sqlite3.OperationalError):
                    worker.analyze_pending(self.conn, None)


FULL_LLM_ENV = {"LLM_BASE_URL": "http://llm.test/v1", "LLM_MODEL": "test-model", "LLM_API_KEY": "secret"}


class LoadLlmTests(unittest.TestCase):
    def load(self, modules: dict, key: str, **env: str) -> tuple[object, str]:
        output = io.StringIO()
        environ = {**FULL_LLM_ENV, "LLM_API_KEY": key, **env}
        with mock.patch.dict(sys.modules, modules), mock.patch.dict("os.environ", environ):
            with contextlib.redirect_stdout(output):
                result = worker.load_llm()
        return result, output.getvalue()

    def test_missing_base_url_or_model_means_no_llm_and_names_what_is_missing(self) -> None:
        analyze = mock.Mock()
        for name in ("LLM_BASE_URL", "LLM_MODEL"):
            with self.subTest(missing=name):
                result, output = self.load({"brain.llm": mock.Mock(analyze=analyze)}, key="secret", **{name: ""})
                self.assertIsNone(result)
                self.assertEqual(output, f"brain: no LLM, rules-only analysis (missing {name})\n")

    def test_missing_module_means_no_llm_and_one_line(self) -> None:
        result, output = self.load({"brain.llm": None}, key="secret")  # None makes the import fail
        self.assertIsNone(result)
        self.assertEqual(len(output.splitlines()), 1)
        self.assertTrue(output.startswith("brain: no LLM, rules-only analysis"))

    def test_empty_key_means_no_llm_and_one_line(self) -> None:
        analyze = mock.Mock()
        for key in ("", "   "):
            with self.subTest(key=key):
                result, output = self.load({"brain.llm": mock.Mock(analyze=analyze)}, key=key)
                self.assertIsNone(result)
                self.assertEqual(output, "brain: no LLM, rules-only analysis (missing LLM_API_KEY)\n")

    def test_module_and_key_present_returns_the_analyze_function(self) -> None:
        analyze = mock.Mock()
        result, output = self.load({"brain.llm": mock.Mock(analyze=analyze)}, key="secret")
        self.assertIs(result, analyze)
        self.assertEqual(output, "")

    def test_the_key_is_never_printed(self) -> None:
        _, output = self.load({"brain.llm": None}, key="super-secret-value")
        self.assertNotIn("super-secret-value", output)


class RunLoopTests(unittest.TestCase):
    def run_loop_until_stopped(self, analyze_results: list) -> list[float]:
        """Run run_loop with analyze_pending replaced; stop after the results are used up."""
        sleeps: list[float] = []

        def fake_sleep(seconds: float) -> None:
            sleeps.append(seconds)
            if len(sleeps) >= len(analyze_results):
                raise StopLoop

        with mock.patch.object(worker, "analyze_pending", side_effect=analyze_results):
            with capture_output():
                with self.assertRaises(StopLoop):
                    worker.run_loop(mock.Mock(), None, fake_sleep)
        return sleeps

    def test_sleeps_two_seconds_between_passes(self) -> None:
        self.assertEqual(self.run_loop_until_stopped([0, 0, 0]), [2.0, 2.0, 2.0])

    def test_database_error_is_printed_and_the_loop_retries(self) -> None:
        output = io.StringIO()
        results = [sqlite3.OperationalError("database is locked"), 1, 0]
        sleeps: list[float] = []

        def fake_sleep(seconds: float) -> None:
            sleeps.append(seconds)
            if len(sleeps) == 3:
                raise StopLoop

        with mock.patch.object(worker, "analyze_pending", side_effect=results) as analyze_pending:
            with contextlib.redirect_stdout(output):
                with self.assertRaises(StopLoop):
                    worker.run_loop(mock.Mock(), None, fake_sleep)
        self.assertEqual(analyze_pending.call_count, 3)
        self.assertIn("database is locked", output.getvalue())


if __name__ == "__main__":
    unittest.main()

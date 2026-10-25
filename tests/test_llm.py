"""Tests for brain/llm.py: config, prompt, request body, tolerant parsing and failure handling.

No test touches the internet. Most use an injected `post`; a few use a local http.server stub.
"""
from __future__ import annotations

import contextlib
import io
import json
import os
import socket
import threading
import time
import unittest
import urllib.error
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from brain import llm
from fixtures.load_fixtures import read_events

ROOT = Path(__file__).resolve().parent.parent
FAKE_KEY = "sk-test-FAKE-KEY-123456"
ALLOWED_LABELS = (
    "recon_only",
    "source_theft",
    "package_publish",
    "credential_harvest",
    "automated_secret_scanner",
    "unknown",
)
SENT_EVENT_FIELDS = {
    "event_id", "ts", "source_ip", "user_agent", "token_kind", "bait_id", "credential_id", "stage",
    "service", "method", "path", "action", "target", "status_code", "result", "routed_to",
}
EXAMPLE_ANALYSIS = json.loads((ROOT / "contracts" / "analysis.example.json").read_text(encoding="utf-8"))


def env(base_url: str = "https://llm.example.test/v1", model: str = "test-model", key: str = FAKE_KEY) -> dict:
    """A full set of LLM env vars."""
    return {"LLM_BASE_URL": base_url, "LLM_MODEL": model, "LLM_API_KEY": key}


def chat_response(content: object) -> dict:
    """What an OpenAI-compatible API returns for one answer."""
    return {"choices": [{"message": {"role": "assistant", "content": content}}]}


def incident_one() -> dict:
    """INC-001 as the worker would pass it (JSON columns already decoded)."""
    return {
        "incident_id": "INC-001", "created_ts": "2026-10-25T10:00:00Z", "updated_ts": "2026-10-25T10:03:00Z",
        "signal_kind": "bait", "confidence": "high", "score": 95, "severity": "critical", "status": "open",
        "source_ips": ["172.30.0.66"], "token_ids": ["BAIT-SRC-01", "BAIT-CI-02"], "stages": ["source", "build"],
        "rules_hit": [
            {"rule": "bait_use", "points": 60, "event_id": "evt_s1000001"},
            {"rule": "second_stage_bait", "points": 20, "event_id": "evt_s1000004"},
            {"rule": "bait_write_or_publish", "points": 15, "event_id": "evt_s1000005"},
        ],
    }


def events_one() -> list[dict]:
    """Scenario 1 events, with extra keys the LLM must never see."""
    events = read_events(["scenario1"])
    for event in events:
        event["incident_id"] = "INC-001"
        event["processed"] = 1
        event["authorization"] = "Bearer SHOULD-NOT-LEAVE"
    return events


def incident_two() -> dict:
    """INC-002 (behavior incident, real token)."""
    return {
        "incident_id": "INC-002", "created_ts": "2026-10-25T10:10:00Z", "updated_ts": "2026-10-25T10:11:00Z",
        "signal_kind": "behavior", "confidence": "medium", "score": 80, "severity": "high",
        "status": "needs_review", "source_ips": ["172.30.0.77"], "token_ids": ["REAL-CI-01"],
        "stages": ["build", "publish"],
        "rules_hit": [{"rule": "new_source", "points": 20, "event_id": "evt_s2000001"}],
    }


def events_two() -> list[dict]:
    return read_events(["scenario2"])


DEFAULT_REPLY = object()  # "use the normal good answer" (None must stay usable as a bad reply)


class FakePost:
    """Replaces the HTTP call: records every call and returns or raises what we tell it."""

    def __init__(self, response: object = DEFAULT_REPLY, error: BaseException | None = None) -> None:
        self.response = chat_response(json.dumps(EXAMPLE_ANALYSIS)) if response is DEFAULT_REPLY else response
        self.error = error
        self.calls: list[dict] = []

    def __call__(self, url: str, headers: dict, payload: dict, timeout: float) -> object:
        self.calls.append({"url": url, "headers": headers, "payload": payload, "timeout": timeout})
        if self.error is not None:
            raise self.error
        return self.response


def run_analyze(fake: FakePost, environ: dict | None = None) -> tuple[dict | None, str]:
    """Call analyze() on incident one with the given env; return (result, printed text)."""
    out = io.StringIO()
    with mock.patch.dict(os.environ, environ if environ is not None else env(), clear=True):
        with contextlib.redirect_stdout(out):
            result = llm.analyze(incident_one(), events_one(), post=fake)
    return result, out.getvalue()


class ConfigTests(unittest.TestCase):
    def test_each_missing_env_var_returns_none_without_a_call(self) -> None:
        for name in ("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY"):
            with self.subTest(missing=name):
                environ = env()
                del environ[name]
                fake = FakePost()
                result, _ = run_analyze(fake, environ)
                self.assertIsNone(result)
                self.assertEqual(fake.calls, [])

    def test_each_empty_or_blank_env_var_returns_none_without_a_call(self) -> None:
        for name in ("LLM_BASE_URL", "LLM_MODEL", "LLM_API_KEY"):
            for blank in ("", "   "):
                with self.subTest(empty=name, value=blank):
                    environ = env()
                    environ[name] = blank
                    fake = FakePost()
                    result, _ = run_analyze(fake, environ)
                    self.assertIsNone(result)
                    self.assertEqual(fake.calls, [])

    def test_no_env_at_all_returns_none(self) -> None:
        fake = FakePost()
        result, _ = run_analyze(fake, {})
        self.assertIsNone(result)
        self.assertEqual(fake.calls, [])

    def test_env_is_read_at_call_time(self) -> None:
        fake = FakePost()
        run_analyze(fake, env(model="model-a"))
        run_analyze(fake, env(model="model-b"))
        self.assertEqual([c["payload"]["model"] for c in fake.calls], ["model-a", "model-b"])


class HappyPathTests(unittest.TestCase):
    def test_returns_the_parsed_dict(self) -> None:
        fake = FakePost()
        result, _ = run_analyze(fake)
        self.assertEqual(result, EXAMPLE_ANALYSIS)
        self.assertEqual(len(fake.calls), 1)

    def test_works_for_the_behavior_incident_too(self) -> None:
        fake = FakePost()
        with mock.patch.dict(os.environ, env(), clear=True):
            result = llm.analyze(incident_two(), events_two(), post=fake)
        self.assertEqual(result, EXAMPLE_ANALYSIS)
        sent = json.loads(fake.calls[0]["payload"]["messages"][1]["content"])
        self.assertEqual(sent["incident"]["incident_id"], "INC-002")
        self.assertEqual(len(sent["events"]), len(events_two()))

    def test_only_content_is_used_not_reasoning_content(self) -> None:
        message = {"content": json.dumps(EXAMPLE_ANALYSIS), "reasoning_content": '{"summary": "wrong"}'}
        result, _ = run_analyze(FakePost(response={"choices": [{"message": message}]}))
        self.assertEqual(result, EXAMPLE_ANALYSIS)

    def test_reasoning_content_alone_is_not_used(self) -> None:
        message = {"content": "", "reasoning_content": json.dumps(EXAMPLE_ANALYSIS)}
        result, _ = run_analyze(FakePost(response={"choices": [{"message": message}]}))
        self.assertIsNone(result)

    def test_no_validation_beyond_json_object(self) -> None:
        result, _ = run_analyze(FakePost(response=chat_response('{"anything": 1}')))
        self.assertEqual(result, {"anything": 1})


class ParsingTests(unittest.TestCase):
    def parse(self, content: object) -> dict | None:
        result, _ = run_analyze(FakePost(response=chat_response(content)))
        return result

    def test_surrounding_whitespace(self) -> None:
        self.assertEqual(self.parse("\n  " + json.dumps(EXAMPLE_ANALYSIS) + "  \n"), EXAMPLE_ANALYSIS)

    def test_json_fence(self) -> None:
        text = "```json\n" + json.dumps(EXAMPLE_ANALYSIS, ensure_ascii=False) + "\n```"
        self.assertEqual(self.parse(text), EXAMPLE_ANALYSIS)

    def test_plain_fence(self) -> None:
        text = "```\n" + json.dumps(EXAMPLE_ANALYSIS) + "\n```"
        self.assertEqual(self.parse(text), EXAMPLE_ANALYSIS)

    def test_prose_around_json(self) -> None:
        text = "Here is the analysis:\n" + json.dumps(EXAMPLE_ANALYSIS) + "\nHope that helps!"
        self.assertEqual(self.parse(text), EXAMPLE_ANALYSIS)

    def test_nested_braces_inside_strings_survive(self) -> None:
        body = {"summary": "نص فيه {أقواس} داخل النص", "observed": []}
        self.assertEqual(self.parse("note: " + json.dumps(body, ensure_ascii=False) + " end"), body)

    def test_not_json_returns_none(self) -> None:
        self.assertIsNone(self.parse("I cannot help with that."))

    def test_json_list_returns_none(self) -> None:
        self.assertIsNone(self.parse('[{"summary": "x"}]'))

    def test_json_scalar_returns_none(self) -> None:
        self.assertIsNone(self.parse('"just a string"'))

    def test_broken_json_returns_none(self) -> None:
        self.assertIsNone(self.parse('{"summary": "cut off", "observed": ['))

    def test_empty_content_returns_none(self) -> None:
        self.assertIsNone(self.parse(""))

    def test_none_content_returns_none(self) -> None:
        self.assertIsNone(self.parse(None))

    def test_non_string_content_returns_none(self) -> None:
        self.assertIsNone(self.parse([{"type": "text", "text": "{}"}]))


class FailureTests(unittest.TestCase):
    def assert_none_without_raising(self, fake: FakePost) -> str:
        result, printed = run_analyze(fake)
        self.assertIsNone(result)
        return printed

    def test_http_errors_return_none_and_print_one_short_line(self) -> None:
        for code in (401, 429, 500):
            with self.subTest(status=code):
                error = urllib.error.HTTPError("https://x.test", code, "msg", {}, io.BytesIO(b""))
                self.addCleanup(error.close)
                printed = self.assert_none_without_raising(FakePost(error=error))
                lines = printed.splitlines()
                self.assertEqual(len(lines), 1)
                self.assertTrue(lines[0].startswith("brain: "))
                self.assertIn(str(code), lines[0])
                self.assertNotIn(FAKE_KEY, printed)

    def test_timeout_returns_none(self) -> None:
        printed = self.assert_none_without_raising(FakePost(error=TimeoutError("timed out")))
        self.assertTrue(printed.startswith("brain: "))
        self.assertIn("TimeoutError", printed)

    def test_url_error_returns_none(self) -> None:
        printed = self.assert_none_without_raising(FakePost(error=urllib.error.URLError("no route")))
        self.assertIn("URLError", printed)

    def test_connection_error_returns_none(self) -> None:
        self.assert_none_without_raising(FakePost(error=ConnectionResetError("reset")))

    def test_unexpected_exception_returns_none(self) -> None:
        self.assert_none_without_raising(FakePost(error=RuntimeError("boom")))

    def test_error_text_never_contains_the_key_even_if_the_exception_does(self) -> None:
        printed = self.assert_none_without_raising(FakePost(error=RuntimeError("bad header " + FAKE_KEY)))
        self.assertNotIn(FAKE_KEY, printed)

    def test_malformed_response_shapes_return_none(self) -> None:
        shapes = [
            None,
            "a string",
            [],
            {},
            {"choices": []},
            {"choices": None},
            {"choices": ["not a dict"]},
            {"choices": [{}]},
            {"choices": [{"message": None}]},
            {"choices": [{"message": "text"}]},
            {"choices": [{"message": {}}]},
            {"error": {"message": "invalid api key"}},
        ]
        for shape in shapes:
            with self.subTest(shape=shape):
                result, _ = run_analyze(FakePost(response=shape))
                self.assertIsNone(result)

    def test_bad_input_does_not_raise(self) -> None:
        fake = FakePost()
        with mock.patch.dict(os.environ, env(), clear=True):
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertIsNone(llm.analyze(None, None, post=fake))  # type: ignore[arg-type]

    def test_missing_prompt_file_returns_none(self) -> None:
        fake = FakePost()
        with mock.patch.object(llm, "PROMPT_PATH", ROOT / "brain" / "prompts" / "does_not_exist.md"):
            result, _ = run_analyze(fake)
        self.assertIsNone(result)
        self.assertEqual(fake.calls, [])


class RequestBodyTests(unittest.TestCase):
    def sent(self) -> tuple[dict, dict]:
        """Run once and return (the single recorded call, the decoded user message)."""
        fake = FakePost()
        run_analyze(fake)
        call = fake.calls[0]
        user = json.loads(call["payload"]["messages"][1]["content"])
        return call, user

    def test_model_temperature_and_messages(self) -> None:
        call, _ = self.sent()
        payload = call["payload"]
        self.assertEqual(payload["model"], "test-model")
        self.assertEqual(payload["temperature"], 0.2)
        self.assertEqual([m["role"] for m in payload["messages"]], ["system", "user"])
        self.assertEqual(payload["messages"][0]["content"], llm.build_system_prompt())

    def test_does_not_send_response_format_or_other_extras(self) -> None:
        call, _ = self.sent()
        self.assertEqual(set(call["payload"]), {"model", "messages", "temperature", "reasoning_effort"})

    def test_reasoning_effort_is_low_by_default(self) -> None:
        # glm-5.3-flash spent ~64s thinking at its default effort; "low" answered in ~13s.
        call, _ = self.sent()
        self.assertEqual(call["payload"]["reasoning_effort"], "low")

    def test_reasoning_effort_comes_from_env(self) -> None:
        fake = FakePost()
        run_analyze(fake, {**env(), "LLM_REASONING_EFFORT": "high"})
        self.assertEqual(fake.calls[0]["payload"]["reasoning_effort"], "high")

    def test_reasoning_effort_none_leaves_the_field_out(self) -> None:
        # For models that reject the field.
        fake = FakePost()
        run_analyze(fake, {**env(), "LLM_REASONING_EFFORT": "none"})
        self.assertNotIn("reasoning_effort", fake.calls[0]["payload"])

    def test_headers_and_timeout(self) -> None:
        call, _ = self.sent()
        self.assertEqual(call["headers"]["Authorization"], "Bearer " + FAKE_KEY)
        self.assertEqual(call["headers"]["Content-Type"], "application/json")
        self.assertEqual(call["timeout"], llm.TIMEOUT_SECONDS)
        self.assertEqual(llm.TIMEOUT_SECONDS, 60)

    def test_user_message_has_incident_and_events(self) -> None:
        _, user = self.sent()
        self.assertEqual(set(user), {"incident", "events"})
        self.assertEqual(user["incident"], incident_one())
        self.assertEqual([e["event_id"] for e in user["events"]], [e["event_id"] for e in events_one()])

    def test_events_only_contain_allowed_fields(self) -> None:
        _, user = self.sent()
        for event in user["events"]:
            self.assertTrue(set(event) <= SENT_EVENT_FIELDS, set(event) - SENT_EVENT_FIELDS)
            self.assertIn("event_id", event)
            self.assertIn("action", event)

    def test_events_keep_their_values(self) -> None:
        _, user = self.sent()
        first = user["events"][0]
        self.assertEqual(first["event_id"], "evt_s1000001")
        self.assertEqual(first["bait_id"], "BAIT-SRC-01")
        self.assertEqual(first["routed_to"], "decoy")

    def test_extra_incident_fields_are_not_sent(self) -> None:
        incident = incident_one()
        incident["secret_note"] = "do not send"
        fake = FakePost()
        with mock.patch.dict(os.environ, env(), clear=True):
            llm.analyze(incident, events_one(), post=fake)
        user = json.loads(fake.calls[0]["payload"]["messages"][1]["content"])
        self.assertNotIn("secret_note", user["incident"])

    def test_no_bait_token_strings_in_the_whole_outgoing_body(self) -> None:
        baits = json.loads((ROOT / "contracts" / "baits.json").read_text(encoding="utf-8"))
        self.assertTrue(baits)
        # Even if an event carried a bait token in a field, no bait token may leave.
        events = events_one()
        events[0]["path"] = "/leak?t=" + baits[0]["token"]
        events[1]["user_agent"] = "x " + baits[1]["token"]
        fake = FakePost()
        with mock.patch.dict(os.environ, env(), clear=True):
            llm.analyze(incident_one(), events, post=fake)
        body = json.dumps(fake.calls[0]["payload"], ensure_ascii=False)
        for bait in baits:
            self.assertNotIn(bait["token"], body)

    def test_bait_token_in_an_event_field_is_replaced_by_its_bait_id(self) -> None:
        baits = json.loads((ROOT / "contracts" / "baits.json").read_text(encoding="utf-8"))
        events = events_one()
        events[0]["path"] = "/leak?t=" + baits[0]["token"]
        fake = FakePost()
        with mock.patch.dict(os.environ, env(), clear=True):
            llm.analyze(incident_one(), events, post=fake)
        user = json.loads(fake.calls[0]["payload"]["messages"][1]["content"])
        self.assertEqual(user["events"][0]["path"], "/leak?t=" + baits[0]["bait_id"])

    def test_missing_baits_file_does_not_break_the_call(self) -> None:
        fake = FakePost()
        with mock.patch.object(llm, "BAITS_PATH", ROOT / "contracts" / "no_such_baits.json"):
            result, _ = run_analyze(fake)
        self.assertEqual(result, EXAMPLE_ANALYSIS)

    def test_clean_fixture_events_contain_no_bait_tokens(self) -> None:
        baits = json.loads((ROOT / "contracts" / "baits.json").read_text(encoding="utf-8"))
        fake = FakePost()
        run_analyze(fake)
        body = json.dumps(fake.calls[0]["payload"], ensure_ascii=False)
        for bait in baits:
            self.assertNotIn(bait["token"], body)

    def test_api_key_and_other_env_are_not_in_the_body(self) -> None:
        environ = env()
        environ["DECOY_GIT_TOKEN"] = "decoy-git-secret-value"
        environ["DECOY_NPM_TOKEN"] = "decoy-npm-secret-value"
        fake = FakePost()
        with mock.patch.dict(os.environ, environ, clear=True):
            llm.analyze(incident_one(), events_one(), post=fake)
        body = json.dumps(fake.calls[0]["payload"], ensure_ascii=False)
        for secret in (FAKE_KEY, "decoy-git-secret-value", "decoy-npm-secret-value", "SHOULD-NOT-LEAVE"):
            self.assertNotIn(secret, body)

    def test_key_only_appears_in_the_authorization_header(self) -> None:
        fake = FakePost()
        run_analyze(fake)
        call = fake.calls[0]
        self.assertNotIn(FAKE_KEY, call["url"])
        for name, value in call["headers"].items():
            if name != "Authorization":
                self.assertNotIn(FAKE_KEY, value)


class UrlTests(unittest.TestCase):
    def url_for(self, base: str) -> str:
        fake = FakePost()
        run_analyze(fake, env(base_url=base))
        return fake.calls[0]["url"]

    def test_base_without_trailing_slash(self) -> None:
        self.assertEqual(self.url_for("https://api.x.ai/v1"), "https://api.x.ai/v1/chat/completions")

    def test_base_with_trailing_slash(self) -> None:
        self.assertEqual(self.url_for("https://api.x.ai/v1/"), "https://api.x.ai/v1/chat/completions")

    def test_base_with_several_slashes_and_spaces(self) -> None:
        self.assertEqual(self.url_for("  https://api.x.ai/v1//  "), "https://api.x.ai/v1/chat/completions")

    def test_glm_style_base(self) -> None:
        self.assertEqual(
            self.url_for("https://open.bigmodel.cn/api/paas/v4"),
            "https://open.bigmodel.cn/api/paas/v4/chat/completions",
        )


class ExtractJsonObjectTests(unittest.TestCase):
    def test_plain(self) -> None:
        self.assertEqual(llm.extract_json_object('{"a": 1}'), {"a": 1})

    def test_fence_with_language_in_caps(self) -> None:
        self.assertEqual(llm.extract_json_object('```JSON\n{"a": 1}\n```'), {"a": 1})

    def test_garbage(self) -> None:
        self.assertIsNone(llm.extract_json_object("no braces here"))
        self.assertIsNone(llm.extract_json_object("} backwards {"))
        self.assertIsNone(llm.extract_json_object(""))


class StubHandler(BaseHTTPRequestHandler):
    """Answers POSTs the way the owning StubServer tells it to, and records what it got."""

    def do_POST(self) -> None:
        stub: StubServer = self.server.stub  # type: ignore[attr-defined]
        length = int(self.headers.get("Content-Length", "0"))
        raw = self.rfile.read(length)
        stub.requests.append({
            "path": self.path,
            "authorization": self.headers.get("Authorization"),
            "content_type": self.headers.get("Content-Type"),
            "body": json.loads(raw.decode("utf-8")),
        })
        time.sleep(stub.delay)
        data = stub.reply_body if isinstance(stub.reply_body, bytes) else json.dumps(stub.reply_body).encode("utf-8")
        try:
            self.send_response(stub.status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)
        except OSError:
            pass  # the client already gave up (timeout test)

    def log_message(self, format: str, *args: object) -> None:  # keep test output quiet
        pass


class StubServer:
    """A threaded http.server on 127.0.0.1 with a random port."""

    def __init__(self) -> None:
        self.requests: list[dict] = []
        self.status = 200
        self.delay = 0.0
        self.reply_body: object = chat_response(json.dumps(EXAMPLE_ANALYSIS))
        self.server = ThreadingHTTPServer(("127.0.0.1", 0), StubHandler)
        self.server.stub = self  # type: ignore[attr-defined]
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.server.server_address[1]}/api/paas/v4"

    def start(self) -> None:
        self.thread.start()

    def stop(self) -> None:
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(timeout=5)


class LocalServerTests(unittest.TestCase):
    """Real urllib path against a local stub: URL joining, headers and body shape."""

    def setUp(self) -> None:
        self.stub = StubServer()
        self.stub.start()
        self.addCleanup(self.stub.stop)

    def analyze(self, base_url: str | None = None) -> dict | None:
        environ = env(base_url=base_url or self.stub.base_url)
        with mock.patch.dict(os.environ, environ, clear=True):
            with contextlib.redirect_stdout(io.StringIO()):
                return llm.analyze(incident_one(), events_one())

    def test_end_to_end_happy_path(self) -> None:
        self.assertEqual(self.analyze(), EXAMPLE_ANALYSIS)
        self.assertEqual(len(self.stub.requests), 1)
        request = self.stub.requests[0]
        self.assertEqual(request["path"], "/api/paas/v4/chat/completions")
        self.assertEqual(request["authorization"], "Bearer " + FAKE_KEY)
        self.assertEqual(request["content_type"], "application/json")
        self.assertEqual(request["body"]["model"], "test-model")
        self.assertEqual(request["body"]["temperature"], 0.2)
        self.assertEqual([m["role"] for m in request["body"]["messages"]], ["system", "user"])
        self.assertNotIn("response_format", request["body"])

    def test_trailing_slash_base_url_hits_the_same_path(self) -> None:
        self.assertEqual(self.analyze(self.stub.base_url + "/"), EXAMPLE_ANALYSIS)
        self.assertEqual(self.stub.requests[0]["path"], "/api/paas/v4/chat/completions")

    def test_arabic_text_survives_the_round_trip(self) -> None:
        result = self.analyze()
        self.assertEqual(result["summary"], EXAMPLE_ANALYSIS["summary"])

    def test_fenced_answer_over_http(self) -> None:
        text = "```json\n" + json.dumps(EXAMPLE_ANALYSIS, ensure_ascii=False) + "\n```"
        self.stub.reply_body = chat_response(text)
        self.assertEqual(self.analyze(), EXAMPLE_ANALYSIS)

    def test_http_401_and_500_return_none(self) -> None:
        for status in (401, 500):
            with self.subTest(status=status):
                self.stub.status = status
                self.stub.reply_body = {"error": {"message": "nope"}}
                self.assertIsNone(self.analyze())

    def test_non_json_body_returns_none(self) -> None:
        self.stub.reply_body = b"<html>gateway error</html>"
        self.assertIsNone(self.analyze())

    def test_timeout_returns_none(self) -> None:
        self.stub.delay = 1.0
        with mock.patch.object(llm, "TIMEOUT_SECONDS", 0.2):
            self.assertIsNone(self.analyze())

    def test_connection_refused_returns_none(self) -> None:
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            port = sock.getsockname()[1]
        self.assertIsNone(self.analyze(f"http://127.0.0.1:{port}/v1"))

    def test_bad_url_scheme_returns_none(self) -> None:
        self.assertIsNone(self.analyze("file:///etc/passwd"))
        self.assertEqual(self.stub.requests, [])


class PromptTests(unittest.TestCase):
    def test_prompt_file_exists_and_loads(self) -> None:
        self.assertTrue(llm.PROMPT_PATH.exists())
        self.assertTrue(llm.load_prompt().strip())

    def test_prompt_mentions_every_allowed_label(self) -> None:
        text = llm.load_prompt()
        for label in ALLOWED_LABELS:
            self.assertIn(label, text)

    def test_prompt_mentions_every_output_key(self) -> None:
        text = llm.load_prompt()
        for key in EXAMPLE_ANALYSIS:
            self.assertIn(key, text)

    def test_prompt_states_the_key_rules(self) -> None:
        text = llm.load_prompt()
        for phrase in ("Arabic", "ONLY a JSON object", "evidence_event_ids", "automated_secret_scanner"):
            self.assertIn(phrase, text)

    def test_system_prompt_embeds_the_example_file_content(self) -> None:
        system = llm.build_system_prompt()
        example = json.loads((ROOT / "contracts" / "analysis.example.json").read_text(encoding="utf-8"))
        self.assertIn(json.dumps(example, ensure_ascii=False, indent=2), system)
        self.assertNotIn("{{", system)  # no unfilled placeholder

    def test_system_prompt_follows_the_example_file_if_it_changes(self) -> None:
        with mock.patch.object(llm, "EXAMPLE_PATH", ROOT / "contracts" / "event.example.json"):
            system = llm.build_system_prompt()
        other = json.loads((ROOT / "contracts" / "event.example.json").read_text(encoding="utf-8"))
        self.assertIn(json.dumps(other, ensure_ascii=False, indent=2), system)

    def test_example_in_prompt_uses_only_allowed_labels(self) -> None:
        self.assertIn(EXAMPLE_ANALYSIS["hypothesis"]["label"], ALLOWED_LABELS)
        for alt in EXAMPLE_ANALYSIS["alternatives"]:
            self.assertIn(alt["label"], ALLOWED_LABELS)


if __name__ == "__main__":
    unittest.main()

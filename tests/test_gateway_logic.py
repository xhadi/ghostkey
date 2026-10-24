"""Tests for gateway/logic.py (pure functions, no mitmproxy needed)."""
from __future__ import annotations

import base64
import hashlib
import json
import unittest

from common import db
from gateway import logic

BAITS = [
    {"bait_id": "BAIT-SRC-01", "token": "bait-src-token", "service": "git", "stage": "source"},
    {"bait_id": "BAIT-CI-02", "token": "bait-ci-token", "service": "npm", "stage": "build"},
]
REAL_TOKEN = "synthetic-real-token"
CREDENTIALS = [
    {"credential_id": "REAL-CI-01", "sha256": hashlib.sha256(REAL_TOKEN.encode()).hexdigest()},
    {"credential_id": "REAL-PLACEHOLDER", "sha256": "FILL_ME: not a hash yet"},
]


def basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


def load_fixture_events() -> list[dict]:
    events = []
    for name in ("scenario1.jsonl", "scenario2.jsonl", "normal.jsonl"):
        for line in (db.ROOT / "fixtures" / name).read_text(encoding="utf-8").splitlines():
            if line.strip():
                events.append(json.loads(line))
    return events


class TokenCandidatesTest(unittest.TestCase):
    def test_token_scheme(self):
        self.assertEqual(logic.token_candidates("token abc"), ["abc"])

    def test_bearer_scheme(self):
        self.assertEqual(logic.token_candidates("Bearer abc"), ["abc"])

    def test_scheme_is_case_insensitive(self):
        self.assertEqual(logic.token_candidates("TOKEN abc"), ["abc"])
        self.assertEqual(logic.token_candidates("bearer abc"), ["abc"])
        self.assertEqual(logic.token_candidates(basic("u", "p").replace("Basic", "BASIC")), ["p", "u"])

    def test_basic_returns_password_first_then_user(self):
        self.assertEqual(logic.token_candidates(basic("alice", "secret")), ["secret", "alice"])

    def test_basic_token_in_username_only(self):
        # http://TOKEN@host sends "TOKEN:" so the password is empty.
        self.assertEqual(logic.token_candidates(basic("tok", "")), ["tok"])

    def test_basic_with_empty_user(self):
        self.assertEqual(logic.token_candidates(basic("", "tok")), ["tok"])

    def test_basic_password_may_contain_colon(self):
        self.assertEqual(logic.token_candidates(basic("u", "a:b")), ["a:b", "u"])

    def test_bad_base64_gives_nothing(self):
        self.assertEqual(logic.token_candidates("Basic !!!not-base64!!!"), [])

    def test_basic_without_colon_gives_nothing(self):
        raw = "Basic " + base64.b64encode(b"nocolon").decode()
        self.assertEqual(logic.token_candidates(raw), [])

    def test_basic_not_utf8_gives_nothing(self):
        raw = "Basic " + base64.b64encode(b"\xff\xfe:\xff").decode()
        self.assertEqual(logic.token_candidates(raw), [])

    def test_missing_or_other_scheme_gives_nothing(self):
        self.assertEqual(logic.token_candidates(None), [])
        self.assertEqual(logic.token_candidates(""), [])
        self.assertEqual(logic.token_candidates("Digest abc"), [])
        self.assertEqual(logic.token_candidates("token"), [])
        self.assertEqual(logic.token_candidates("Bearer   "), [])


class ClassifyTokenTest(unittest.TestCase):
    def test_bait_match(self):
        result = logic.classify_token(["bait-src-token"], BAITS, CREDENTIALS)
        self.assertEqual(result["token_kind"], "bait")
        self.assertEqual(result["bait_id"], "BAIT-SRC-01")
        self.assertIsNone(result["credential_id"])
        self.assertEqual(result["bait"], BAITS[0])

    def test_real_match_by_sha256(self):
        result = logic.classify_token([REAL_TOKEN], BAITS, CREDENTIALS)
        self.assertEqual(result["token_kind"], "real")
        self.assertEqual(result["credential_id"], "REAL-CI-01")
        self.assertIsNone(result["bait_id"])
        self.assertIsNone(result["bait"])

    def test_unknown_token(self):
        result = logic.classify_token(["whatever"], BAITS, CREDENTIALS)
        self.assertEqual(result["token_kind"], "unknown")
        self.assertIsNone(result["bait_id"])
        self.assertIsNone(result["credential_id"])

    def test_no_candidates_is_none(self):
        result = logic.classify_token([], BAITS, CREDENTIALS)
        self.assertEqual(result["token_kind"], "none")
        self.assertIsNone(result["bait"])

    def test_bait_in_username_found_when_password_is_junk(self):
        result = logic.classify_token(["junk", "bait-ci-token"], BAITS, CREDENTIALS)
        self.assertEqual(result["bait_id"], "BAIT-CI-02")

    def test_bait_beats_real_even_when_real_is_first(self):
        result = logic.classify_token([REAL_TOKEN, "bait-ci-token"], BAITS, CREDENTIALS)
        self.assertEqual(result["token_kind"], "bait")

    def test_placeholder_hash_never_matches(self):
        for junk in ("FILL_ME: not a hash yet", "", "FILL_ME"):
            result = logic.classify_token([junk], BAITS, CREDENTIALS)
            self.assertEqual(result["token_kind"], "unknown")

    def test_bait_match_is_exact(self):
        result = logic.classify_token(["bait-src-token "], BAITS, CREDENTIALS)
        self.assertEqual(result["token_kind"], "unknown")


class ClassifyActionGitTest(unittest.TestCase):
    def check(self, method, path, expected):
        self.assertEqual(logic.classify_action("git", method, path), expected)

    def test_list_repos(self):
        self.check("GET", "/api/v1/user/repos", ("list_repos", None))
        self.check("GET", "/api/v1/user/repos?limit=50&page=1", ("list_repos", None))
        self.check("GET", "/api/v1/repos/search?q=ci", ("list_repos", None))

    def test_clone(self):
        self.check("GET", "/ops/ci-pipeline.git/info/refs?service=git-upload-pack", ("clone", "ops/ci-pipeline"))
        self.check("POST", "/ops/ci-pipeline.git/git-upload-pack", ("clone", "ops/ci-pipeline"))

    def test_clone_without_dot_git_suffix(self):
        self.check("POST", "/ops/ci-pipeline/git-upload-pack", ("clone", "ops/ci-pipeline"))

    def test_push(self):
        self.check("GET", "/dev/payments-api.git/info/refs?service=git-receive-pack", ("push", "dev/payments-api"))
        self.check("POST", "/dev/payments-api.git/git-receive-pack", ("push", "dev/payments-api"))

    def test_api_read_has_repo_target(self):
        self.check("GET", "/api/v1/user", ("api_read", None))
        self.check("GET", "/api/v1/repos/ops/ci-pipeline", ("api_read", "ops/ci-pipeline"))
        self.check("GET", "/api/v1/repos/ops/ci-pipeline/contents/.npmrc?ref=main", ("api_read", "ops/ci-pipeline"))

    def test_api_write(self):
        self.check("POST", "/api/v1/repos/ops/ci-pipeline/issues", ("api_write", "ops/ci-pipeline"))
        self.check("DELETE", "/api/v1/repos/ops/ci-pipeline", ("api_write", "ops/ci-pipeline"))
        self.check("POST", "/api/v1/user/repos", ("api_write", None))
        self.check("POST", "/api/v1/repos/migrate", ("api_write", None))

    def test_search_post_is_a_write_not_list(self):
        self.check("POST", "/api/v1/repos/search", ("api_write", None))

    def test_other(self):
        self.check("GET", "/", ("other", None))
        self.check("GET", "/user/login", ("other", None))
        self.check("GET", "/ops/ci-pipeline", ("other", None))
        self.check("GET", "/ops/ci-pipeline.git/info/refs?service=something-else", ("other", None))
        self.check("GET", "/ops/ci-pipeline.git/info/refs", ("other", None))

    def test_wrong_method_for_git_service_is_other(self):
        self.check("GET", "/ops/ci-pipeline.git/git-upload-pack", ("other", None))
        self.check("POST", "/ops/ci-pipeline.git/info/refs?service=git-upload-pack", ("other", None))

    def test_percent_encoded_repo_path_is_decoded(self):
        self.check("POST", "/ops/ci%2Dpipeline.git/git-upload-pack", ("clone", "ops/ci-pipeline"))


class ClassifyActionNpmTest(unittest.TestCase):
    def check(self, method, path, expected):
        self.assertEqual(logic.classify_action("npm", method, path), expected)

    def test_login(self):
        self.check("GET", "/-/whoami", ("login", None))

    def test_search(self):
        self.check("GET", "/-/v1/search?text=kfu&size=20", ("search", None))

    def test_publish_all_scoped_spellings(self):
        for path in ("/@kfu%2fbuild-utils", "/@kfu%2Fbuild-utils", "/@kfu/build-utils"):
            self.check("PUT", path, ("publish", "@kfu/build-utils"))

    def test_publish_unscoped(self):
        self.check("PUT", "/left-pad", ("publish", "left-pad"))

    def test_install(self):
        self.check("GET", "/@kfu%2fbuild-utils", ("install", "@kfu/build-utils"))
        self.check("GET", "/@kfu%2fbuild-utils?write=true", ("install", "@kfu/build-utils"))
        self.check("GET", "/left-pad", ("install", "left-pad"))

    def test_install_tarball(self):
        self.check("GET", "/@kfu/build-utils/-/build-utils-1.0.0.tgz", ("install", "@kfu/build-utils"))
        self.check("GET", "/@kfu%2fbuild-utils/-/build-utils-1.0.0.tgz", ("install", "@kfu/build-utils"))
        self.check("GET", "/left-pad/-/left-pad-1.3.0.tgz", ("install", "left-pad"))

    def test_other(self):
        self.check("GET", "/-/ping", ("other", None))
        self.check("GET", "/", ("other", None))
        self.check("PUT", "/-/user/org.couchdb.user:ci-bot", ("other", None))
        self.check("POST", "/-/npm/v1/security/advisories/bulk", ("other", None))
        self.check("POST", "/@kfu%2fbuild-utils", ("other", None))
        self.check("DELETE", "/@kfu%2fbuild-utils/-rev/3-abc", ("other", None))
        self.check("PUT", "/@kfu%2fbuild-utils/-rev/3-abc", ("other", None))
        self.check("POST", "/-/whoami", ("other", None))

    def test_unknown_service_is_other(self):
        self.assertEqual(logic.classify_action("ftp", "GET", "/x"), ("other", None))


class FixtureTest(unittest.TestCase):
    """The fixtures are the contract: our classification must reproduce them."""

    def test_classify_action_matches_every_fixture_event(self):
        for event in load_fixture_events():
            with self.subTest(event_id=event["event_id"]):
                got = logic.classify_action(event["service"], event["method"], event["path"])
                self.assertEqual(got, (event["action"], event["target"]))


class StageForTest(unittest.TestCase):
    def test_bait_uses_its_own_stage(self):
        bait = {"bait_id": "BAIT-CI-02", "stage": "build"}
        self.assertEqual(logic.stage_for("bait", bait, "publish"), "build")
        self.assertEqual(logic.stage_for("bait", bait, "other"), "build")

    def test_everything_else_derives_stage_from_action(self):
        expected = {
            "list_repos": "source", "clone": "source", "api_read": "source", "api_write": "source",
            "login": "build", "install": "build", "search": "build",
            "push": "publish", "publish": "publish",
            "other": "unknown",
        }
        for token_kind in ("real", "unknown", "none"):
            for action, stage in expected.items():
                with self.subTest(token_kind=token_kind, action=action):
                    self.assertEqual(logic.stage_for(token_kind, None, action), stage)

    def test_unlisted_action_is_unknown(self):
        self.assertEqual(logic.stage_for("none", None, "something_new"), "unknown")


class SessionIdTest(unittest.TestCase):
    def test_known_values(self):
        self.assertEqual(logic.session_id("172.30.0.66", "BAIT-SRC-01", None), "s_24c8a2d5")
        self.assertEqual(logic.session_id("172.30.0.10", None, "REAL-CI-01"), "s_eb9d21da")

    def test_anonymous(self):
        expected = "s_" + hashlib.sha1(b"172.30.0.5|anon").hexdigest()[:8]
        self.assertEqual(logic.session_id("172.30.0.5", None, None), expected)

    def test_bait_id_wins_over_credential_id(self):
        self.assertEqual(
            logic.session_id("1.2.3.4", "BAIT-X", "REAL-Y"),
            logic.session_id("1.2.3.4", "BAIT-X", None),
        )


class NormalizeIpTest(unittest.TestCase):
    def test_strips_ipv4_mapped_prefix(self):
        self.assertEqual(logic.normalize_ip("::ffff:172.30.0.66"), "172.30.0.66")
        self.assertEqual(logic.normalize_ip("::FFFF:172.30.0.66"), "172.30.0.66")

    def test_plain_addresses_unchanged(self):
        self.assertEqual(logic.normalize_ip("172.30.0.66"), "172.30.0.66")
        self.assertEqual(logic.normalize_ip("::1"), "::1")
        self.assertEqual(logic.normalize_ip("fe80::1"), "fe80::1")


class ResultForTest(unittest.TestCase):
    def test_upstream_failure_is_error(self):
        self.assertEqual(logic.result_for(None, "install", None), "error")

    def test_auth_failures_are_denied(self):
        self.assertEqual(logic.result_for(401, "install", b""), "denied")
        self.assertEqual(logic.result_for(403, "clone", b""), "denied")

    def test_success_codes_are_ok(self):
        for code in (200, 201, 204, 301, 302, 304):
            self.assertEqual(logic.result_for(code, "install", b"{}"), "ok")

    def test_other_codes_are_error(self):
        for code in (400, 404, 409, 500, 502, 503):
            self.assertEqual(logic.result_for(code, "install", b""), "error")

    def test_login_with_empty_object_is_denied(self):
        self.assertEqual(logic.result_for(200, "login", b"{}"), "denied")

    def test_login_with_username_is_ok(self):
        self.assertEqual(logic.result_for(200, "login", b'{"username": "ci-bot"}'), "ok")
        self.assertEqual(logic.result_for(200, "login", '{"username": "ci-bot"}'), "ok")

    def test_login_with_odd_bodies_is_denied(self):
        for body in (b"", None, b"not json", b"[]", b'"username"', b'{"user": "x"}', b"\xff\xfe"):
            with self.subTest(body=body):
                self.assertEqual(logic.result_for(200, "login", body), "denied")

    def test_login_failure_codes_keep_their_meaning(self):
        self.assertEqual(logic.result_for(401, "login", b"{}"), "denied")
        self.assertEqual(logic.result_for(500, "login", b"{}"), "error")

    def test_body_is_ignored_for_other_actions(self):
        self.assertEqual(logic.result_for(200, "install", b"{}"), "ok")
        self.assertEqual(logic.result_for(200, "install", None), "ok")


ENV = {
    "DECOY_GIT_URL": "http://gitea-decoy:3000",
    "DECOY_GIT_TOKEN": "decoy-git-synthetic",
    "DECOY_NPM_URL": "http://verdaccio-decoy:4873",
    "DECOY_NPM_TOKEN": "decoy-npm-synthetic",
}


class RouteForTest(unittest.TestCase):
    def test_bait_on_git_goes_to_decoy_with_token_scheme(self):
        self.assertEqual(
            logic.route_for("bait", "git", ENV),
            {
                "routed_to": "decoy",
                "upstream": "http://gitea-decoy:3000",
                "authorization": "token decoy-git-synthetic",
            },
        )

    def test_bait_on_npm_goes_to_decoy_with_bearer_scheme(self):
        self.assertEqual(
            logic.route_for("bait", "npm", ENV),
            {
                "routed_to": "decoy",
                "upstream": "http://verdaccio-decoy:4873",
                "authorization": "Bearer decoy-npm-synthetic",
            },
        )

    def test_bait_with_missing_or_empty_decoy_settings_is_blocked(self):
        for missing in ENV:
            for value in (None, ""):
                env = dict(ENV)
                if value is None:
                    del env[missing]
                else:
                    env[missing] = value
                service = "git" if "GIT" in missing else "npm"
                with self.subTest(missing=missing, value=value):
                    self.assertEqual(logic.route_for("bait", service, env), {"routed_to": "blocked"})

    def test_bait_with_unknown_service_is_blocked(self):
        self.assertEqual(logic.route_for("bait", "ftp", ENV), {"routed_to": "blocked"})

    def test_missing_settings_of_the_other_service_do_not_matter(self):
        env = {k: v for k, v in ENV.items() if "NPM" not in k}
        self.assertEqual(logic.route_for("bait", "git", env)["routed_to"], "decoy")

    def test_non_bait_goes_to_real_unchanged(self):
        for kind in ("real", "unknown", "none"):
            self.assertEqual(logic.route_for(kind, "git", ENV), {"routed_to": "real"})
            self.assertEqual(logic.route_for(kind, "npm", {}), {"routed_to": "real"})


class NewEventIdTest(unittest.TestCase):
    def test_format(self):
        self.assertRegex(logic.new_event_id(), r"^evt_[0-9a-f]{8}$")

    def test_ids_differ(self):
        self.assertEqual(len({logic.new_event_id() for _ in range(50)}), 50)


class BuildEventTest(unittest.TestCase):
    def test_has_every_db_column_with_defaults(self):
        token = logic.classify_token([], BAITS, CREDENTIALS)
        event = logic.build_event(
            ts="2026-10-25T10:00:00Z", source_ip="172.30.0.5", user_agent=None, service="npm",
            method="GET", path="/-/ping", token=token, action="other", target=None,
            routed_to="real", status_code=None, result="error",
        )
        self.assertEqual(set(event), set(db.EVENT_COLUMNS))
        self.assertRegex(event["event_id"], r"^evt_[0-9a-f]{8}$")
        self.assertIsNone(event["incident_id"])
        self.assertEqual(event["processed"], 0)
        self.assertEqual(event["token_kind"], "none")
        self.assertEqual(event["stage"], "unknown")

    def test_explicit_event_id_is_used(self):
        token = logic.classify_token([], BAITS, CREDENTIALS)
        event = logic.build_event(
            ts="t", source_ip="1.1.1.1", user_agent="ua", service="git", method="GET", path="/",
            token=token, action="other", target=None, routed_to="real", status_code=200,
            result="ok", event_id="evt_deadbeef",
        )
        self.assertEqual(event["event_id"], "evt_deadbeef")

    def test_reproduces_every_fixture_event(self):
        baits = {bait["bait_id"]: bait for bait in db.load_json("baits.json")}
        for fixture in load_fixture_events():
            with self.subTest(event_id=fixture["event_id"]):
                token = {
                    "token_kind": fixture["token_kind"],
                    "bait_id": fixture["bait_id"],
                    "credential_id": fixture["credential_id"],
                    "bait": baits.get(fixture["bait_id"]),
                }
                built = logic.build_event(
                    ts=fixture["ts"], source_ip=fixture["source_ip"], user_agent=fixture["user_agent"],
                    service=fixture["service"], method=fixture["method"], path=fixture["path"],
                    token=token, action=fixture["action"], target=fixture["target"],
                    routed_to=fixture["routed_to"], status_code=fixture["status_code"],
                    result=fixture["result"],
                )
                self.assertEqual(built, fixture | {"event_id": built["event_id"]})


if __name__ == "__main__":
    unittest.main()

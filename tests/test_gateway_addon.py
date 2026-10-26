"""Tests for gateway/addon.py. They need mitmproxy, so they run in the gateway container.

On a host without mitmproxy the whole file is skipped.
"""
from __future__ import annotations

import base64
import hashlib
import io
import tempfile
import unittest
from contextlib import redirect_stdout
from pathlib import Path

from common import db

try:
    from mitmproxy import http
    from mitmproxy.test import taddons, tflow

    HAVE_MITMPROXY = True
except ImportError:
    HAVE_MITMPROXY = False

if HAVE_MITMPROXY:
    from gateway import addon  # a real import error here must fail loudly, not skip

GIT_PORT = 8080
NPM_PORT = 8081
BAIT_GIT = "synthetic-bait-git-token"
BAIT_NPM = "synthetic-bait-npm-token"
REAL_TOKEN = "synthetic-real-ci-token"
DECOY_GIT = "synthetic-decoy-git-token"
DECOY_NPM = "synthetic-decoy-npm-token"
ALL_SECRETS = (BAIT_GIT, BAIT_NPM, REAL_TOKEN, DECOY_GIT, DECOY_NPM)

BAITS = [
    {"bait_id": "BAIT-SRC-01", "token": BAIT_GIT, "service": "git", "stage": "source"},
    {"bait_id": "BAIT-CI-02", "token": BAIT_NPM, "service": "npm", "stage": "build"},
]
CREDENTIALS = [
    {"credential_id": "REAL-CI-01", "sha256": hashlib.sha256(REAL_TOKEN.encode()).hexdigest()},
]
ENV = {
    "DECOY_GIT_URL": "http://gitea-decoy:3000",
    "DECOY_GIT_TOKEN": DECOY_GIT,
    "DECOY_NPM_URL": "http://verdaccio-decoy:4873",
    "DECOY_NPM_TOKEN": DECOY_NPM,
}


def basic(user: str, password: str) -> str:
    return "Basic " + base64.b64encode(f"{user}:{password}".encode()).decode()


@unittest.skipUnless(HAVE_MITMPROXY, "mitmproxy is not installed (run in the gateway container)")
class GatewayAddonTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.db_path = Path(tmp.name) / "test.db"
        self.ctx = None
        self.addCleanup(self.stop_gateway)
        self.start_gateway(ENV)

    def start_gateway(self, env: dict) -> None:
        self.gateway = addon.Gateway(
            db_path=self.db_path, baits=BAITS, credentials=CREDENTIALS, env=env,
        )
        self.ctx = taddons.context(self.gateway)  # runs the addon's load hook
        self.ctx.__enter__()

    def stop_gateway(self) -> None:
        if self.ctx is not None:
            self.ctx.__exit__(None, None, None)
            self.ctx = None
            self.gateway.done()

    def restart_gateway(self, env: dict) -> None:
        self.stop_gateway()
        self.start_gateway(env)

    # --- helpers -------------------------------------------------------------

    def make_flow(
        self,
        method: str = "GET",
        path: str = "/",
        auth: str | None = None,
        port: int = GIT_PORT,
        peer: str = "172.30.0.66",
        user_agent: str = "curl/8.5.0",
    ):
        headers = {"User-Agent": user_agent}
        if auth is not None:
            headers["Authorization"] = auth
        real_host = {GIT_PORT: "gitea-real", NPM_PORT: "verdaccio-real"}.get(port, "other-real")
        request = http.Request.make(method, f"http://{real_host}:3000{path}", b"", headers)
        flow = tflow.tflow(req=request)
        flow.request.headers["Host"] = f"gateway:{port}"  # what the client sent
        flow.client_conn.peername = (peer, 51000)
        flow.client_conn.sockname = ("172.30.0.2", port)
        return flow

    def answer(self, flow, status: int = 200, body: bytes = b"{}") -> None:
        flow.response = http.Response.make(status, body, {"Content-Type": "application/json"})
        self.gateway.response(flow)

    def rows(self) -> list[dict]:
        conn = db.connect(self.db_path)
        try:
            return [dict(row) for row in conn.execute("SELECT * FROM events ORDER BY ts, rowid")]
        finally:
            conn.close()

    def only_row(self) -> dict:
        rows = self.rows()
        self.assertEqual(len(rows), 1)
        return rows[0]

    # --- bait traffic --------------------------------------------------------

    def test_bait_on_git_is_pointed_at_the_decoy(self):
        flow = self.make_flow(auth=f"token {BAIT_GIT}", path="/api/v1/user/repos")
        self.gateway.request(flow)
        self.assertEqual(flow.request.scheme, "http")
        self.assertEqual(flow.request.host, "gitea-decoy")
        self.assertEqual(flow.request.port, 3000)
        self.assertEqual(flow.request.headers.get_all("Authorization"), [f"token {DECOY_GIT}"])
        self.assertEqual(flow.request.headers["Host"], "gateway:8080")  # the client's Host is kept
        self.assertIsNone(flow.response)

    def test_bait_on_git_event_row(self):
        flow = self.make_flow(auth=f"token {BAIT_GIT}", path="/api/v1/user/repos")
        self.gateway.request(flow)
        self.answer(flow, 200, b"[]")
        row = self.only_row()
        self.assertEqual(row["token_kind"], "bait")
        self.assertEqual(row["bait_id"], "BAIT-SRC-01")
        self.assertIsNone(row["credential_id"])
        self.assertEqual(row["routed_to"], "decoy")
        self.assertEqual(row["stage"], "source")
        self.assertEqual(row["service"], "git")
        self.assertEqual(row["action"], "list_repos")
        self.assertEqual(row["method"], "GET")
        self.assertEqual(row["path"], "/api/v1/user/repos")
        self.assertEqual(row["status_code"], 200)
        self.assertEqual(row["result"], "ok")
        self.assertEqual(row["source_ip"], "172.30.0.66")
        self.assertEqual(row["user_agent"], "curl/8.5.0")
        self.assertEqual(row["session_id"], "s_24c8a2d5")
        self.assertRegex(row["event_id"], r"^evt_[0-9a-f]{8}$")
        self.assertRegex(row["ts"], r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ$")
        self.assertIsNone(row["incident_id"])
        self.assertEqual(row["processed"], 0)

    def test_git_basic_auth_bait_gets_decoy_token_scheme(self):
        flow = self.make_flow(
            method="POST", path="/ops/ci-pipeline.git/git-upload-pack", auth=basic("git", BAIT_GIT),
        )
        self.gateway.request(flow)
        self.assertEqual(flow.request.host, "gitea-decoy")
        self.assertEqual(flow.request.headers.get_all("Authorization"), [f"token {DECOY_GIT}"])
        self.answer(flow)
        row = self.only_row()
        self.assertEqual((row["action"], row["target"]), ("clone", "ops/ci-pipeline"))
        self.assertEqual(row["bait_id"], "BAIT-SRC-01")

    def test_bait_in_username_of_basic_auth_is_found(self):
        flow = self.make_flow(auth=basic(BAIT_GIT, ""))
        self.gateway.request(flow)
        self.assertEqual(flow.request.host, "gitea-decoy")

    def test_bait_on_npm_uses_bearer_and_decoy_registry(self):
        flow = self.make_flow(
            method="PUT", path="/@kfu%2fbuild-utils", auth=f"Bearer {BAIT_NPM}", port=NPM_PORT,
            user_agent="npm/10.8.2 node/v20.18.0 linux x64",
        )
        self.gateway.request(flow)
        self.assertEqual(flow.request.host, "verdaccio-decoy")
        self.assertEqual(flow.request.port, 4873)
        self.assertEqual(flow.request.headers.get_all("Authorization"), [f"Bearer {DECOY_NPM}"])
        self.assertEqual(flow.request.headers["Host"], "gateway:8081")
        self.answer(flow, 201, b'{"ok": true}')
        row = self.only_row()
        self.assertEqual(row["service"], "npm")
        self.assertEqual(row["bait_id"], "BAIT-CI-02")
        self.assertEqual(row["stage"], "build")
        self.assertEqual((row["action"], row["target"]), ("publish", "@kfu/build-utils"))
        self.assertEqual(row["path"], "/@kfu%2fbuild-utils")
        self.assertEqual(row["routed_to"], "decoy")
        self.assertEqual(row["session_id"], "s_36a5a296")

    def test_bait_in_a_second_authorization_header_is_still_caught(self):
        flow = self.make_flow(auth="token junk", path="/api/v1/user/repos")
        flow.request.headers.add("Authorization", f"Bearer {BAIT_GIT}")
        self.gateway.request(flow)
        self.assertEqual(flow.request.host, "gitea-decoy")
        self.assertEqual(flow.request.headers.get_all("Authorization"), [f"token {DECOY_GIT}"])
        self.answer(flow)
        row = self.only_row()
        self.assertEqual((row["token_kind"], row["bait_id"], row["routed_to"]), ("bait", "BAIT-SRC-01", "decoy"))

    def test_decoy_path_and_method_are_untouched(self):
        flow = self.make_flow(method="PUT", path="/@kfu%2fbuild-utils", auth=f"Bearer {BAIT_NPM}", port=NPM_PORT)
        self.gateway.request(flow)
        self.assertEqual(flow.request.method, "PUT")
        self.assertEqual(flow.request.path, "/@kfu%2fbuild-utils")

    # --- bait with no decoy configured ---------------------------------------

    def test_bait_without_decoy_settings_is_blocked_with_503(self):
        self.restart_gateway({"DECOY_GIT_URL": "http://gitea-decoy:3000", "DECOY_GIT_TOKEN": ""})
        flow = self.make_flow(auth=f"token {BAIT_GIT}", path="/api/v1/user/repos")
        self.gateway.request(flow)
        self.assertEqual(flow.response.status_code, 503)
        self.assertEqual(flow.request.host, "gitea-real")  # never re-pointed or forwarded
        self.assertEqual(flow.request.headers["Authorization"], f"token {BAIT_GIT}")
        row = self.only_row()
        self.assertEqual(row["routed_to"], "blocked")
        self.assertEqual(row["token_kind"], "bait")
        self.assertEqual(row["status_code"], 503)
        self.assertEqual(row["result"], "error")

    def test_blocked_flow_gets_exactly_one_event_even_if_response_hook_runs(self):
        self.restart_gateway({})
        flow = self.make_flow(auth=f"token {BAIT_GIT}")
        self.gateway.request(flow)
        self.gateway.response(flow)  # mitmproxy may call this for a locally made response
        self.assertEqual(len(self.rows()), 1)

    # --- non-bait traffic ----------------------------------------------------

    def test_real_token_is_forwarded_unchanged(self):
        flow = self.make_flow(
            method="GET", path="/@kfu%2fbuild-utils", auth=f"Bearer {REAL_TOKEN}", port=NPM_PORT,
            peer="172.30.0.10", user_agent="npm/10.8.2 node/v20.18.0 linux x64",
        )
        self.gateway.request(flow)
        self.assertEqual(flow.request.host, "verdaccio-real")
        self.assertEqual(flow.request.port, 3000)
        self.assertEqual(flow.request.headers.get_all("Authorization"), [f"Bearer {REAL_TOKEN}"])
        self.assertEqual(flow.request.headers["Host"], "gateway:8081")
        self.answer(flow, 200, b'{"name": "@kfu/build-utils"}')
        row = self.only_row()
        self.assertEqual(row["token_kind"], "real")
        self.assertEqual(row["credential_id"], "REAL-CI-01")
        self.assertIsNone(row["bait_id"])
        self.assertEqual(row["routed_to"], "real")
        self.assertEqual(row["stage"], "build")
        self.assertEqual((row["action"], row["target"]), ("install", "@kfu/build-utils"))
        self.assertEqual(row["session_id"], "s_" + hashlib.sha1(b"172.30.0.10|REAL-CI-01").hexdigest()[:8])

    def test_real_token_publish_event_has_publish_stage(self):
        flow = self.make_flow(
            method="PUT", path="/@kfu%2fbuild-utils", auth=f"Bearer {REAL_TOKEN}", port=NPM_PORT,
        )
        self.gateway.request(flow)
        self.answer(flow, 201)
        row = self.only_row()
        self.assertEqual((row["action"], row["stage"]), ("publish", "publish"))

    def test_unknown_token_is_forwarded_unchanged(self):
        flow = self.make_flow(auth="token somethingelse", path="/api/v1/user")
        self.gateway.request(flow)
        self.assertEqual(flow.request.host, "gitea-real")
        self.assertEqual(flow.request.headers["Authorization"], "token somethingelse")
        self.answer(flow, 401)
        row = self.only_row()
        self.assertEqual(row["token_kind"], "unknown")
        self.assertEqual(row["routed_to"], "real")
        self.assertEqual(row["result"], "denied")
        self.assertEqual(row["stage"], "source")

    def test_no_auth_header(self):
        flow = self.make_flow(path="/-/ping", port=NPM_PORT)
        self.gateway.request(flow)
        self.assertEqual(flow.request.host, "verdaccio-real")
        self.assertNotIn("Authorization", flow.request.headers)
        self.answer(flow, 200, b"{}")
        row = self.only_row()
        self.assertEqual(row["token_kind"], "none")
        self.assertEqual(row["routed_to"], "real")
        self.assertEqual(row["action"], "other")
        self.assertEqual(row["stage"], "unknown")
        self.assertEqual(row["session_id"], "s_" + hashlib.sha1(b"172.30.0.66|anon").hexdigest()[:8])

    def test_a_failed_save_does_not_block_later_saves(self):
        self.gateway.conn.execute("PRAGMA busy_timeout=0")  # fail at once instead of after 5 s
        other = db.connect(self.db_path)
        self.addCleanup(other.close)
        other.execute("BEGIN IMMEDIATE")  # another process holds the write lock
        flow = self.make_flow(path="/")
        self.gateway.request(flow)
        with redirect_stdout(io.StringIO()) as output:
            self.answer(flow)
        self.assertIn("could not save event", output.getvalue())
        other.rollback()
        # A real token makes the gateway read `actions`. Inside a failed transaction that read
        # keeps an old snapshot, and after another process writes, every insert would fail.
        flow = self.make_flow(path="/api/v1/user/repos", auth=f"token {REAL_TOKEN}")
        self.gateway.request(flow)
        other.execute("CREATE TABLE another_write (x)")
        other.commit()
        self.answer(flow)
        self.assertEqual(len(self.rows()), 1)

    def test_missing_user_agent_is_stored_as_null(self):
        flow = self.make_flow(path="/")
        del flow.request.headers["User-Agent"]
        self.gateway.request(flow)
        self.answer(flow)
        self.assertIsNone(self.only_row()["user_agent"])

    def test_ipv4_mapped_peer_address_is_normalized(self):
        flow = self.make_flow(auth=f"token {BAIT_GIT}", peer="::ffff:172.30.0.66")
        self.gateway.request(flow)
        self.answer(flow)
        row = self.only_row()
        self.assertEqual(row["source_ip"], "172.30.0.66")
        self.assertEqual(row["session_id"], "s_" + hashlib.sha1(b"172.30.0.66|BAIT-SRC-01").hexdigest()[:8])

    # --- results -------------------------------------------------------------

    def test_whoami_with_empty_object_is_denied(self):
        flow = self.make_flow(path="/-/whoami", auth=f"Bearer {BAIT_NPM}", port=NPM_PORT)
        self.gateway.request(flow)
        self.answer(flow, 200, b"{}")
        row = self.only_row()
        self.assertEqual((row["action"], row["status_code"], row["result"]), ("login", 200, "denied"))

    def test_whoami_with_username_is_ok(self):
        flow = self.make_flow(path="/-/whoami", auth=f"Bearer {BAIT_NPM}", port=NPM_PORT)
        self.gateway.request(flow)
        self.answer(flow, 200, b'{"username": "decoy-bot"}')
        self.assertEqual(self.only_row()["result"], "ok")

    def test_error_hook_records_status_none_and_result_error(self):
        flow = self.make_flow(auth=f"token {BAIT_GIT}", path="/api/v1/user/repos")
        self.gateway.request(flow)
        flow.error = tflow.terr()
        self.gateway.error(flow)
        row = self.only_row()
        self.assertIsNone(row["status_code"])
        self.assertEqual(row["result"], "error")
        self.assertEqual(row["routed_to"], "decoy")
        self.assertEqual(row["bait_id"], "BAIT-SRC-01")

    def test_error_after_response_does_not_add_a_second_event(self):
        flow = self.make_flow(path="/")
        self.gateway.request(flow)
        self.answer(flow)
        flow.error = tflow.terr()
        self.gateway.error(flow)
        self.assertEqual(len(self.rows()), 1)

    def test_response_hook_twice_does_not_add_a_second_event(self):
        flow = self.make_flow(path="/")
        self.gateway.request(flow)
        self.answer(flow)
        self.gateway.response(flow)
        self.assertEqual(len(self.rows()), 1)

    # --- other ports ---------------------------------------------------------

    def test_unknown_port_is_not_touched_and_not_logged(self):
        flow = self.make_flow(auth=f"token {BAIT_GIT}", port=9999)
        self.gateway.request(flow)
        self.assertEqual(flow.request.host, "other-real")
        self.assertEqual(flow.request.headers["Authorization"], f"token {BAIT_GIT}")
        self.assertIsNone(flow.response)
        self.answer(flow)
        flow.error = tflow.terr()
        self.gateway.error(flow)
        self.assertEqual(self.rows(), [])

    # --- containment of a real credential ------------------------------------

    def add_revoke(self, status: str, mode: str | None, scope_ip: str | None, decided_ts: str = "2026-10-25T10:00:00Z") -> None:
        """Insert an incident and a revoke_credential action for REAL-CI-01."""
        conn = db.connect(self.db_path)
        try:
            conn.execute(
                "INSERT OR IGNORE INTO incidents (incident_id, created_ts, updated_ts, signal_kind, confidence,"
                " score, severity, status) VALUES ('INC-001', ?, ?, 'behavior', 'medium', 80, 'high', 'needs_review')",
                (decided_ts, decided_ts),
            )
            conn.execute(
                "INSERT INTO actions (incident_id, ts, kind, target, tier, status, decided_by, decided_ts, scope_ip, mode)"
                " VALUES ('INC-001', ?, 'revoke_credential', 'REAL-CI-01', 'approval', ?, 'tester', ?, ?, ?)",
                (decided_ts, status, decided_ts, scope_ip, mode),
            )
            conn.commit()
        finally:
            conn.close()

    def npm_get(self, peer: str):
        return self.make_flow(
            path="/@kfu%2fbuild-utils", auth=f"Bearer {REAL_TOKEN}", port=NPM_PORT, peer=peer,
        )

    def test_block_answers_403_and_records_blocked_event(self):
        self.add_revoke("approved", "block", "172.30.0.77")
        flow = self.npm_get("172.30.0.77")
        self.gateway.request(flow)
        self.assertEqual(flow.response.status_code, 403)
        self.assertEqual(flow.response.content, b"forbidden")
        self.assertEqual(flow.request.host, "verdaccio-real")  # never re-pointed
        row = self.only_row()
        self.assertEqual(row["routed_to"], "blocked")
        self.assertEqual(row["status_code"], 403)
        self.assertEqual(row["result"], "denied")
        self.assertEqual(row["token_kind"], "real")
        self.assertEqual(row["credential_id"], "REAL-CI-01")

    def test_divert_goes_to_decoy_with_decoy_credential(self):
        self.add_revoke("approved", "divert", "172.30.0.77")
        flow = self.npm_get("172.30.0.77")
        self.gateway.request(flow)
        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.host, "verdaccio-decoy")
        self.assertEqual(flow.request.headers.get_all("Authorization"), [f"Bearer {DECOY_NPM}"])
        self.answer(flow, 200, b"{}")
        row = self.only_row()
        self.assertEqual(row["routed_to"], "decoy")
        self.assertEqual(row["token_kind"], "real")
        self.assertEqual(row["credential_id"], "REAL-CI-01")

    def test_divert_without_decoy_settings_answers_503(self):
        self.restart_gateway({})
        self.add_revoke("approved", "divert", "172.30.0.77")
        flow = self.npm_get("172.30.0.77")
        self.gateway.request(flow)
        self.assertEqual(flow.response.status_code, 503)
        self.assertEqual(flow.request.host, "verdaccio-real")
        row = self.only_row()
        self.assertEqual((row["routed_to"], row["status_code"], row["result"]), ("blocked", 503, "error"))

    def test_same_credential_other_ip_is_untouched(self):
        self.add_revoke("approved", "block", "172.30.0.77")
        flow = self.npm_get("172.30.0.10")
        self.gateway.request(flow)
        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.host, "verdaccio-real")
        self.assertEqual(flow.request.headers.get_all("Authorization"), [f"Bearer {REAL_TOKEN}"])
        self.answer(flow)
        self.assertEqual(self.only_row()["routed_to"], "real")

    def test_pending_or_rejected_decision_has_no_effect(self):
        self.add_revoke("pending", None, "172.30.0.77")
        self.add_revoke("rejected", "block", "172.30.0.77")
        flow = self.npm_get("172.30.0.77")
        self.gateway.request(flow)
        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.host, "verdaccio-real")
        self.answer(flow)
        self.assertEqual(self.only_row()["routed_to"], "real")

    def test_newest_approved_decision_wins(self):
        self.add_revoke("approved", "block", "172.30.0.77", "2026-10-25T10:00:00Z")
        self.add_revoke("approved", "divert", "172.30.0.77", "2026-10-25T10:05:00Z")
        flow = self.npm_get("172.30.0.77")
        self.gateway.request(flow)
        self.assertEqual(flow.request.host, "verdaccio-decoy")

    def test_containment_does_not_apply_to_baits_or_other_credentials(self):
        self.add_revoke("approved", "block", "172.30.0.77")
        flow = self.make_flow(auth=f"token {BAIT_GIT}", path="/api/v1/user/repos", peer="172.30.0.77")
        self.gateway.request(flow)
        self.assertIsNone(flow.response)
        self.assertEqual(flow.request.host, "gitea-decoy")

    def test_failed_containment_lookup_fails_closed(self):
        self.gateway.conn.close()  # the lookup will now raise
        flow = self.npm_get("172.30.0.77")
        out = io.StringIO()
        with redirect_stdout(out):
            self.gateway.request(flow)
        self.assertEqual(flow.response.status_code, 503)
        self.assertEqual(flow.request.host, "verdaccio-real")
        self.assertNotIn(REAL_TOKEN, out.getvalue())

    # --- never store a token -------------------------------------------------

    def test_no_event_column_contains_any_token(self):
        flows = [
            self.make_flow(auth=f"token {BAIT_GIT}", path="/api/v1/user/repos"),
            self.make_flow(auth=basic("git", BAIT_GIT), path="/ops/x.git/git-upload-pack", method="POST"),
            self.make_flow(auth=basic(BAIT_GIT, ""), path="/"),
            self.make_flow(auth=f"Bearer {BAIT_NPM}", path="/-/whoami", port=NPM_PORT),
            self.make_flow(auth=f"Bearer {REAL_TOKEN}", path="/@kfu%2fbuild-utils", port=NPM_PORT),
            self.make_flow(auth="token not-a-known-token-xyz", path="/"),
        ]
        for flow in flows:
            self.gateway.request(flow)
            self.answer(flow)
        errored = self.make_flow(auth=f"token {BAIT_GIT}", path="/")
        self.gateway.request(errored)
        errored.error = tflow.terr()
        self.gateway.error(errored)
        self.add_revoke("approved", "block", "172.30.0.77")  # contained real-token paths
        blocked = self.npm_get("172.30.0.77")
        self.gateway.request(blocked)
        self.add_revoke("approved", "divert", "172.30.0.78")
        diverted = self.npm_get("172.30.0.78")
        self.gateway.request(diverted)
        self.answer(diverted)
        rows = self.rows()
        self.assertEqual(len(rows), len(flows) + 3)
        everything = " ".join(str(value) for row in rows for value in row.values())
        for secret in ALL_SECRETS + ("not-a-known-token-xyz",):
            self.assertNotIn(secret, everything)
        for secret in ALL_SECRETS:
            self.assertNotIn(base64.b64encode(secret.encode()).decode(), everything)

    # --- robustness ----------------------------------------------------------

    def test_exception_in_request_hook_fails_closed_and_prints_no_secret(self):
        def explode(*args, **kwargs):
            raise RuntimeError(f"boom {BAIT_GIT}")

        self.gateway._route_request = explode
        flow = self.make_flow(auth=f"token {BAIT_GIT}")
        out = io.StringIO()
        with redirect_stdout(out):
            self.gateway.request(flow)  # must not raise
        self.assertEqual(flow.response.status_code, 503)  # never forwarded unchecked
        self.assertNotIn(BAIT_GIT, out.getvalue())
        self.assertTrue(out.getvalue().strip())  # but it says something

    def test_exception_in_response_hook_is_swallowed_and_next_request_works(self):
        flow = self.make_flow(path="/")
        self.gateway.request(flow)
        self.gateway.conn.close()  # inserting will now fail
        flow.response = http.Response.make(200, b"{}")
        out = io.StringIO()
        with redirect_stdout(out):
            self.gateway.response(flow)  # must not raise
        for secret in ALL_SECRETS:
            self.assertNotIn(secret, out.getvalue())
        self.gateway.conn = db.connect(self.db_path)  # DB comes back
        flow2 = self.make_flow(path="/")
        self.gateway.request(flow2)
        self.answer(flow2)
        self.assertEqual(len(self.rows()), 1)

    def test_load_hook_creates_tables_in_a_fresh_db(self):
        conn = db.connect(self.db_path)
        try:
            tables = {r[0] for r in conn.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        finally:
            conn.close()
        self.assertIn("events", tables)


@unittest.skipUnless(HAVE_MITMPROXY, "mitmproxy is not installed (run in the gateway container)")
class ModuleLevelTest(unittest.TestCase):
    def test_addons_list_has_one_gateway(self):
        self.assertEqual(len(addon.addons), 1)
        self.assertIsInstance(addon.addons[0], addon.Gateway)

    def test_default_constructor_reads_contract_files_and_env(self):
        with tempfile.TemporaryDirectory() as tmp:
            gateway = addon.Gateway(db_path=Path(tmp) / "x.db", env=ENV)
            gateway.start()
            try:
                bait_ids = {b["bait_id"] for b in gateway.baits}
                self.assertIn("BAIT-SRC-01", bait_ids)
                self.assertTrue(gateway.credentials)
            finally:
                gateway.done()

    def test_real_baits_json_token_is_routed_to_decoy(self):
        real_bait = db.load_json("baits.json")[0]
        with tempfile.TemporaryDirectory() as tmp:
            gateway = addon.Gateway(db_path=Path(tmp) / "x.db", env=ENV)
            with taddons.context(gateway):
                request = http.Request.make(
                    "GET", "http://gitea-real:3000/api/v1/user/repos", b"",
                    {"Authorization": f"token {real_bait['token']}"},
                )
                flow = tflow.tflow(req=request)
                flow.client_conn.peername = ("172.30.0.66", 40000)
                flow.client_conn.sockname = ("172.30.0.2", GIT_PORT)
                gateway.request(flow)
                self.assertEqual(flow.request.host, "gitea-decoy")
                gateway.done()


if __name__ == "__main__":
    unittest.main()

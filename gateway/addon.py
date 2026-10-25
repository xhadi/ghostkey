"""mitmproxy addon: the Ghostkey gateway.

Run with:  mitmdump -s gateway/addon.py --mode reverse:<git>@8080 --mode reverse:<npm>@8081 ...
Port 8080 is Gitea (git), port 8081 is Verdaccio (npm).

For every request we:
  1. look for a bait or real token in the Authorization header,
  2. send bait traffic to the decoy service with the decoy credential (never to the real one),
     and apply an approved Block/Divert decision to one real credential from one source IP,
  3. write exactly one row to the `events` table once the answer (or an error) is known.
The token itself is never stored or printed.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path
from urllib.parse import urlsplit

# mitmdump loads this file as a plain script, so the repo root is not on sys.path yet.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from mitmproxy import http  # noqa: E402

from common import db  # noqa: E402
from gateway import logic  # noqa: E402

SERVICE_BY_PORT = {8080: "git", 8081: "npm"}
ENV_NAMES = ("DECOY_GIT_URL", "DECOY_GIT_TOKEN", "DECOY_NPM_URL", "DECOY_NPM_TOKEN")
META_KEY = "ghostkey"  # key in flow.metadata where we keep what we decided about a request


class Gateway:
    def __init__(
        self,
        db_path: Path | str | None = None,
        baits: list[dict] | None = None,
        credentials: list[dict] | None = None,
        env: dict | None = None,
    ) -> None:
        """Every argument is optional. Tests pass their own; production reads files and env."""
        self.db_path = db_path or db.DB_PATH
        self.baits = baits
        self.credentials = credentials
        self.env = env if env is not None else {name: os.environ.get(name, "") for name in ENV_NAMES}
        self.conn = None

    # --- mitmproxy hooks -----------------------------------------------------

    def load(self, loader) -> None:
        self.start()

    def done(self) -> None:
        if self.conn is not None:
            self.conn.close()
            self.conn = None

    def request(self, flow: http.HTTPFlow) -> None:
        try:
            self._route_request(flow)
        except Exception as exc:  # never kill the proxy; never forward a request we could not check
            flow.metadata.pop(META_KEY, None)
            flow.response = http.Response.make(503, b"gateway error", {"Content-Type": "text/plain"})
            print(f"ghostkey gateway: request hook failed ({type(exc).__name__}), answered 503")

    def response(self, flow: http.HTTPFlow) -> None:
        try:
            self._record(flow, flow.response.status_code, flow.response)
        except Exception as exc:
            print(f"ghostkey gateway: could not save event ({type(exc).__name__})")

    def error(self, flow: http.HTTPFlow) -> None:
        try:
            self._record(flow, None, None)
        except Exception as exc:
            print(f"ghostkey gateway: could not save event ({type(exc).__name__})")

    # --- steps ---------------------------------------------------------------

    def start(self) -> None:
        """Open the DB and read the contract files. Safe to call more than once."""
        if self.conn is not None:
            return
        self.conn = db.connect(self.db_path)
        db.init(self.conn)
        if self.baits is None:
            self.baits = db.load_json("baits.json")
        if self.credentials is None:
            self.credentials = db.load_json("credentials.json")

    def _route_request(self, flow: http.HTTPFlow) -> None:
        self.start()
        service = SERVICE_BY_PORT.get(flow.client_conn.sockname[1])
        if service is None:
            return  # not one of our ports: leave it alone
        request = flow.request
        candidates = []
        for header_value in request.headers.get_all("authorization"):  # a client may send several
            candidates += logic.token_candidates(header_value)
        token = logic.classify_token(candidates, self.baits, self.credentials)
        action, target = logic.classify_action(service, request.method, request.path)
        source_ip = logic.normalize_ip(flow.client_conn.peername[0])
        route = logic.route_for(token["token_kind"], service, self.env)
        if token["token_kind"] == "real":
            mode = self.containment_mode(token["credential_id"], source_ip)
            route = logic.containment_route(mode, service, self.env) or route
        flow.metadata[META_KEY] = {
            "ts": db.now_iso(),
            "service": service,
            "source_ip": source_ip,
            "user_agent": request.headers.get("user-agent"),
            "method": request.method,
            "path": request.path,
            "token": token,
            "action": action,
            "target": target,
            "routed_to": route["routed_to"],
            "saved": False,
        }
        if route["routed_to"] == "blocked":
            status, body = route.get("status", 503), route.get("body", b"blocked")
            flow.response = http.Response.make(status, body, {"Content-Type": "text/plain"})
            self._record(flow, status, None)  # the response hook may not run for our own answer
        elif route["routed_to"] == "decoy":
            point_at_decoy(flow, route["upstream"], route["authorization"])

    def containment_mode(self, credential_id: str, source_ip: str) -> str | None:
        """Newest approved revoke decision for this credential from this IP: 'block', 'divert' or None."""
        row = self.conn.execute(
            "SELECT mode FROM actions WHERE kind='revoke_credential' AND status='approved'"
            " AND target=? AND scope_ip=? ORDER BY decided_ts DESC, action_id DESC LIMIT 1",
            (credential_id, source_ip),
        ).fetchone()
        return row["mode"] if row else None

    def _record(self, flow: http.HTTPFlow, status_code: int | None, response: http.Response | None) -> None:
        """Write the event for this flow, once."""
        meta = flow.metadata.get(META_KEY)
        if meta is None or meta["saved"]:
            return
        body = None
        if response is not None and meta["action"] == "login":
            body = response.get_content(strict=False)  # only whoami needs its body read
        event = logic.build_event(
            ts=meta["ts"],
            source_ip=meta["source_ip"],
            user_agent=meta["user_agent"],
            service=meta["service"],
            method=meta["method"],
            path=meta["path"],
            token=meta["token"],
            action=meta["action"],
            target=meta["target"],
            routed_to=meta["routed_to"],
            status_code=status_code,
            result=logic.result_for(status_code, meta["action"], body),
        )
        db.insert_event(self.conn, event)
        self.conn.commit()
        meta["saved"] = True


def point_at_decoy(flow: http.HTTPFlow, upstream: str, authorization: str) -> None:
    """Send this request to the decoy service with the decoy credential. Keep the client's Host."""
    url = urlsplit(upstream)
    client_host = flow.request.headers.get("host")
    flow.request.scheme = url.scheme
    flow.request.host = url.hostname
    flow.request.port = url.port or (443 if url.scheme == "https" else 80)
    if client_host is not None:
        flow.request.headers["host"] = client_host  # setting .host above rewrote it
    flow.request.headers["authorization"] = authorization  # replaces every Authorization header


addons = [Gateway()]

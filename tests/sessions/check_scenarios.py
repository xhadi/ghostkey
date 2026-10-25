"""Check the CLAUDE.md "Demo scenarios" acceptance results against the live DB.

Run after the three client scripts (normal.sh, scenario1.sh, scenario2.sh):
    docker compose run --rm --no-deps core python -m tests.sessions.check_scenarios

Prints PASS/FAIL per check and exits with 1 if any check failed.
"""
from __future__ import annotations

import json
import sys

from common import db

NORMAL_IP = "172.30.0.10"
SCENARIO1_IP = "172.30.0.66"
SCENARIO2_IP = "172.30.0.77"

failures: list[str] = []


def check(ok: bool, label: str, detail: str = "") -> None:
    print(f"  {'PASS' if ok else 'FAIL'}  {label}" + (f"   [{detail}]" if detail else ""))
    if not ok:
        failures.append(label)


def rows(conn, sql: str, args: tuple = ()) -> list[dict]:
    return [dict(r) for r in conn.execute(sql, args).fetchall()]


def events_of(conn, ip: str) -> list[dict]:
    return rows(conn, "SELECT * FROM events WHERE source_ip = ? ORDER BY ts, rowid", (ip,))


def incidents_of(conn, ip: str) -> list[dict]:
    found = []
    for incident in rows(conn, "SELECT * FROM incidents ORDER BY incident_id"):
        if ip in json.loads(incident["source_ips"]):
            found.append(incident)
    return found


def print_event_table(conn, ip: str, label: str) -> None:
    print(f"\n{label} events from {ip}:")
    print(f"  {'ts':<20} {'method':<5} {'path':<52} {'action':<10} {'target':<18} {'token':<6} {'routed':<6} {'result':<6} incident")
    for e in events_of(conn, ip):
        path = e["path"] if len(e["path"]) <= 52 else e["path"][:49] + "..."
        print(f"  {e['ts']:<20} {e['method']:<5} {path:<52} {e['action']:<10} {str(e['target'] or '-'):<18} "
              f"{e['token_kind']:<6} {e['routed_to']:<6} {str(e['result']):<6} {e['incident_id'] or '-'}")


def count_actions(conn, incident_id: str, kind: str, status: str, target: str | None = None) -> int:
    sql = "SELECT COUNT(*) FROM actions WHERE incident_id = ? AND kind = ? AND status = ?"
    args: tuple = (incident_id, kind, status)
    if target is not None:
        sql += " AND target = ?"
        args += (target,)
    return conn.execute(sql, args).fetchone()[0]


def check_normal(conn) -> None:
    print(f"\nNormal traffic ({NORMAL_IP}):")
    events = events_of(conn, NORMAL_IP)
    check(len(events) > 0, "the gateway recorded events", f"{len(events)} events")
    signals = conn.execute(
        "SELECT COUNT(*) FROM signals WHERE event_id IN (SELECT event_id FROM events WHERE source_ip = ?)", (NORMAL_IP,)
    ).fetchone()[0]
    check(signals == 0, "zero signals", f"{signals} signals")
    found = incidents_of(conn, NORMAL_IP)
    check(not found, "zero incidents involving this IP", f"{len(found)} incidents")
    linked = [e for e in events if e["incident_id"]]
    check(not linked, "no event is linked to an incident", f"{len(linked)} linked")


def check_scenario1(conn) -> None:
    print(f"\nScenario 1 - leaked bait ({SCENARIO1_IP}):")
    events = events_of(conn, SCENARIO1_IP)
    found = incidents_of(conn, SCENARIO1_IP)
    check(len(found) == 1, "exactly 1 incident", f"{len(found)}")
    check(all(e["routed_to"] == "decoy" for e in events) and bool(events), "every event routed_to=decoy",
          f"{sorted({e['routed_to'] for e in events})}")
    check(not [e for e in events if e["routed_to"] == "real"], "zero events routed to real")
    if len(found) != 1:
        return
    inc = found[0]
    check(inc["signal_kind"] == "bait", "signal_kind=bait", inc["signal_kind"])
    check(inc["confidence"] == "high", "confidence=high", inc["confidence"])
    check(inc["score"] == 95, "score 95 (60+20+15)", str(inc["score"]))
    check(inc["severity"] == "critical", "severity=critical", inc["severity"])
    check(json.loads(inc["stages"]) == ["source", "build"], 'stages ["source","build"]', inc["stages"])
    check(inc["status"] == "open", "status=open", inc["status"])
    check(all(e["incident_id"] == inc["incident_id"] for e in events), "all events belong to this incident")
    check(count_actions(conn, inc["incident_id"], "notify", "done") == 1, "exactly one notify action done")
    notify_total = conn.execute("SELECT COUNT(*) FROM actions WHERE incident_id = ? AND kind = 'notify'", (inc["incident_id"],)).fetchone()[0]
    check(notify_total == 1, "no extra notify rows", str(notify_total))
    for bait_id in json.loads(inc["token_ids"]):
        check(count_actions(conn, inc["incident_id"], "disable_bait", "done", bait_id) == 1,
              f"one disable_bait done for {bait_id}")
    check_analysis(conn, inc["incident_id"])


def check_analysis(conn, incident_id: str) -> None:
    analysis = conn.execute("SELECT * FROM analyses WHERE incident_id = ?", (incident_id,)).fetchone()
    check(analysis is not None, "analysis exists")
    if analysis is None:
        return
    body = json.loads(analysis["body"])
    labels = [a.get("label") for a in body.get("alternatives", [])]
    print(f"        analysis source={analysis['source']} valid={analysis['valid']} "
          f"based_on_event_count={analysis['based_on_event_count']} hypothesis={body.get('hypothesis', {}).get('label')}")
    check("automated_secret_scanner" in labels, "analyst alternatives include automated_secret_scanner", str(labels))


def check_scenario2(conn) -> None:
    print(f"\nScenario 2 - stolen real credential ({SCENARIO2_IP}):")
    events = events_of(conn, SCENARIO2_IP)
    found = incidents_of(conn, SCENARIO2_IP)
    check(len(found) == 1, "exactly 1 incident", f"{len(found)}")
    check(bool(events) and all(e["routed_to"] == "real" for e in events), "every event routed_to=real",
          f"{sorted({e['routed_to'] for e in events})}")
    if len(found) != 1:
        return
    inc = found[0]
    check(inc["signal_kind"] == "behavior", "signal_kind=behavior", inc["signal_kind"])
    check(inc["confidence"] == "medium", "confidence=medium", inc["confidence"])
    check(inc["score"] == 80, "score 80 (20+25+35)", str(inc["score"]))
    check(inc["severity"] == "high", "severity=high", inc["severity"])
    check(inc["status"] == "needs_review", "status=needs_review", inc["status"])
    check(count_actions(conn, inc["incident_id"], "notify", "done") == 1, "exactly one notify action done")
    check(count_actions(conn, inc["incident_id"], "revoke_credential", "pending") == 1, "exactly one revoke_credential pending")


def main() -> None:
    conn = db.connect()
    total = conn.execute("SELECT COUNT(*) FROM incidents").fetchone()[0]
    print(f"incidents in DB: {total}")
    for ip, label in ((NORMAL_IP, "Normal"), (SCENARIO1_IP, "Scenario 1"), (SCENARIO2_IP, "Scenario 2")):
        print_event_table(conn, ip, label)
    check_normal(conn)
    check_scenario1(conn)
    check_scenario2(conn)
    print()
    if failures:
        print(f"{len(failures)} check(s) FAILED")
        sys.exit(1)
    print("All checks passed.")


if __name__ == "__main__":
    main()

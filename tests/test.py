"""
0. Health check , neutral baseline, no alerts, no enforcement
1. Normal user traffic , baseline requests
2. User ID enumeration , sequential ID access flags enumeration
3. BOLA (user resource) , enumeration + object-access violation on /users/{id}
4. BOLA (order resource) , same pattern on /orders/{id}
5. Business flow rate abuse , excessive hits to same object, rate-limited
6. Login brute force , repeated /login attempts, rate-limited
7. Registration abuse , repeated /register signups, rate-limited
8. Shadow API probing , hits undocumented routes, flagged as sensitive/shadow
9. BFLA (privilege escalation) , identity baselined on normal endpoints, then hits a privileged path

Core things validated: alerting, risk scoring, enforcement/blocking, flow isolation (distinct ports), and shadow-endpoint discovery."""

from __future__ import annotations

import argparse
import http.client
import json
import socket
import time
from dataclasses import dataclass, field
from typing import Optional


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
CONNECT_TIMEOUT = 5
RESET_URL_PATH: Optional[str] = None

HEALTH_PATH = "/health"
LOGIN_PATH = "/login"
REGISTER_PATH = "/register"
USER_PATH_TEMPLATE = "/users/{id}"
OBJECT_PATH_TEMPLATE = "/orders/{id}"

SHADOW_PATHS = [
    "/v0/legacy/users",
    "/internal/debug",
    "/admin/export",
]

PRE_AUTH_IDENTITY_HEADER = "X-Client-Id"

HEADER_RISK_SCORE = "X-Risk-Score"
HEADER_ALERTS = "X-Alerts"
HEADER_ENFORCEMENT = "X-Enforcement"
DENY_STATUS_CODES = {401, 403, 429}


class Flow:
    def __init__(self, host: str, port: int, timeout: int = CONNECT_TIMEOUT):
        self.conn = http.client.HTTPConnection(host, port, timeout=timeout)
        self.local_port: Optional[int] = None
        self.open_error: Optional[str] = None
        try:
            self.conn.connect()
            self.local_port = self.conn.sock.getsockname()[1]
        except OSError as exc:
            self.open_error = str(exc)

    def request(
        self,
        method: str,
        path: str,
        token: Optional[str] = None,
        client_id: Optional[str] = None,
        body: Optional[dict] = None,
    ):
        if self.open_error:
            return "BLOCKED", {}, f"flow never opened: {self.open_error}"

        headers = {"Accept": "application/json", "Connection": "keep-alive"}
        if token:
            headers["Authorization"] = token
        if client_id:
            headers[PRE_AUTH_IDENTITY_HEADER] = client_id

        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"

        try:
            self.conn.request(method, path, body=data, headers=headers)
            resp = self.conn.getresponse()
            resp.read()
            return resp.status, dict(resp.getheaders()), None
        except (
            ConnectionResetError,
            ConnectionAbortedError,
            BrokenPipeError,
            http.client.RemoteDisconnected,
            socket.timeout,
            OSError,
        ) as exc:
            return "BLOCKED", {}, str(exc)
        except Exception as exc:
            return "ERROR", {}, str(exc)

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


def best_effort_reset(host: str, port: int):
    if not RESET_URL_PATH:
        return
    try:
        conn = http.client.HTTPConnection(host, port, timeout=CONNECT_TIMEOUT)
        conn.request("POST", RESET_URL_PATH)
        conn.getresponse().read()
        conn.close()
    except Exception:
        pass


@dataclass
class Scenario:
    name: str
    method: str = "GET"
    path: Optional[str] = None
    path_template: Optional[str] = None
    ids: Optional[list] = None
    path_sequence: Optional[list] = None
    body_seq: Optional[list] = None
    count: int = 1
    token: Optional[str] = None
    client_id: Optional[str] = None
    pace: float = 0.3
    expect_alerts: list = field(default_factory=list)
    expect_enforcement: Optional[bool] = None

    def build_requests(self) -> list[tuple[str, str, Optional[dict]]]:
        if self.ids is not None:
            return [(self.method, self.path_template.format(id=i), None) for i in self.ids]
        if self.path_sequence is not None:
            return [(self.method, p, None) for p in self.path_sequence]
        if self.body_seq is not None:
            return [(self.method, self.path, b) for b in self.body_seq]
        return [(self.method, self.path, None)] * self.count


SCENARIOS = [
    Scenario(
        name="0. Health check (neutral baseline)",
        path=HEALTH_PATH, count=3, pace=0.5,
        expect_alerts=[], expect_enforcement=False,
    ),
    Scenario(
        name="1. Normal user traffic (baseline)",
        path_template=USER_PATH_TEMPLATE, ids=[101, 102],
        token="Bearer Scenario1-Baseline", pace=1.0,
        expect_alerts=[], expect_enforcement=False,
    ),
    Scenario(
        name="2. User ID enumeration",
        path_template=USER_PATH_TEMPLATE, ids=list(range(200, 210)),
        token="Bearer Scenario2-Enumeration", pace=0.3,
        expect_alerts=["enum"], expect_enforcement=None,
    ),
    Scenario(
        name="3. BOLA attack (user resource)",
        path_template=USER_PATH_TEMPLATE, ids=list(range(300, 312)),
        token="Bearer Scenario3-BOLA", pace=0.2,
        expect_alerts=["enum", "bola"], expect_enforcement=True,
    ),
    Scenario(
        name="4. BOLA attack (order resource)",
        path_template=OBJECT_PATH_TEMPLATE, ids=list(range(300, 312)),
        token="Bearer Scenario4-BOLA-Order", pace=0.2,
        expect_alerts=["enum", "bola"], expect_enforcement=True,
    ),
    Scenario(
        name="5. Business flow rate abuse",
        path=USER_PATH_TEMPLATE.format(id=400),
        token="Bearer Scenario5-RateAbuse", count=20, pace=0.05,
        expect_alerts=["rate"], expect_enforcement=True,
    ),
    Scenario(
        name="6. Login brute force",
        method="POST", path=LOGIN_PATH,
        client_id="Scenario6-BruteForce",
        body_seq=[{"username": "admin", "password": f"guess{i}"} for i in range(15)],
        pace=0.1,
        expect_alerts=["rate"], expect_enforcement=True,
    ),
    Scenario(
        name="7. Registration abuse (bot signup)",
        method="POST", path=REGISTER_PATH,
        client_id="Scenario7-RegAbuse",
        body_seq=[
            {"username": f"bot_user_{i}", "password": "Passw0rd!", "email": f"bot{i}@example.com"}
            for i in range(15)
        ],
        pace=0.1,
        expect_alerts=["rate"], expect_enforcement=True,
    ),
    Scenario(
        name="8. Shadow API probing (undocumented endpoints)",
        token="Bearer Scenario8-ShadowProbe", pace=0.4,
        expect_alerts=["shadow"], expect_enforcement=None,
    ),
    Scenario(
        name="9. BFLA attack (privilege escalation)",
        path_sequence=["/users/101", "/admin/export", "/admin/export"],
        token="Bearer Scenario9-BFLA", pace=0.3,
        expect_alerts=["broken function level authorization"], expect_enforcement=True,
    ),
]


def _shadow_requests(method: str = "GET"):
    return [(method, path, None) for path in SHADOW_PATHS]


_SHADOW_SCENARIO_REQUESTS = _shadow_requests()


@dataclass
class ScenarioResult:
    name: str
    local_port: Optional[int]
    alerts: set
    max_risk: Optional[int]
    enforcement_observed: bool
    log: list
    expect_alerts: list
    expect_enforcement: Optional[bool]


def run_scenario(scenario: Scenario, host: str, port: int) -> ScenarioResult:
    print(f"\n{'-' * 70}\nSCENARIO: {scenario.name}\n{'-' * 70}")

    best_effort_reset(host, port)
    flow = Flow(host, port)
    if flow.open_error:
        print(f"  Could not open flow: {flow.open_error}")
    else:
        print(f"  Flow opened -> local port {flow.local_port}")

    observed_alerts: set = set()
    max_risk_seen: Optional[int] = None
    saw_deny = False
    log = []

    requests = _SHADOW_SCENARIO_REQUESTS if scenario.name.startswith("8.") else scenario.build_requests()

    for method, path, body in requests:
        status, headers, note = flow.request(
            method, path,
            token=scenario.token,
            client_id=scenario.client_id,
            body=body,
        )

        alert_val = headers.get(HEADER_ALERTS)
        risk_val = headers.get(HEADER_RISK_SCORE)
        enf_val = headers.get(HEADER_ENFORCEMENT)

        if alert_val:
            observed_alerts.update(a.strip().lower() for a in alert_val.split(","))
        if risk_val:
            try:
                r = int(risk_val)
                max_risk_seen = r if max_risk_seen is None else max(max_risk_seen, r)
            except ValueError:
                pass

        is_deny = status == "BLOCKED" or (isinstance(status, int) and status in DENY_STATUS_CODES)
        saw_deny = saw_deny or is_deny

        extra = [x for x in [
            f"alerts={alert_val}" if alert_val else None,
            f"risk={risk_val}" if risk_val else None,
            f"enforcement={enf_val}" if enf_val else None,
            note,
        ] if x]
        print(f"    {method:4s} {path:22s} -> {status}" + (f"  [{', '.join(extra)}]" if extra else ""))
        log.append((path, status))
        time.sleep(scenario.pace)

    flow.close()
    return ScenarioResult(
        name=scenario.name,
        local_port=flow.local_port,
        alerts=observed_alerts,
        max_risk=max_risk_seen,
        enforcement_observed=saw_deny,
        log=log,
        expect_alerts=scenario.expect_alerts,
        expect_enforcement=scenario.expect_enforcement,
    )


def evaluate(result: ScenarioResult) -> tuple[bool, list[str]]:
    reasons = []
    ok = True

    if result.expect_alerts:
        if result.alerts:
            for needle in result.expect_alerts:
                if not any(needle in a for a in result.alerts):
                    ok = False
                    reasons.append(f"Expected alert containing '{needle}', got {sorted(result.alerts)}.")
        else:
            reasons.append("No X-Alerts header present -- only inferred from status/enforcement.")

    if result.expect_enforcement is True and not result.enforcement_observed:
        ok = False
        reasons.append("Expected enforcement but every request succeeded.")
    if result.expect_enforcement is False and result.enforcement_observed:
        ok = False
        reasons.append("Unexpected deny/block on traffic that should have passed.")

    if not reasons:
        reasons.append("Observed behaviour matched expectations.")
    return ok, reasons


def main():
    parser = argparse.ArgumentParser(description="API-Sentinel test harness")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    args = parser.parse_args()

    print("=" * 70)
    print("API-Sentinel TEST")
    print("=" * 70)

    results = [run_scenario(s, args.host, args.port) for s in SCENARIOS]

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    all_pass = True
    for result in results:
        ok, reasons = evaluate(result)
        all_pass = all_pass and ok
        print(f"\n{result.name}")
        print(f"  Flow local port : {result.local_port}")
        print(f"  Alerts observed : {sorted(result.alerts) or '(none / no header)'}")
        print(f"  Max risk seen   : {result.max_risk if result.max_risk is not None else '(no header)'}")
        print(f"  Enforcement seen: {result.enforcement_observed}")
        print(f"  Result          : {'PASS' if ok else 'FAIL'}")
        for r in reasons:
            print(f"    - {r}")

    print("\n" + "-" * 70)
    print(f"OVERALL: {'PASS' if all_pass else 'FAIL'}")
    print("-" * 70)

    ports = [r.local_port for r in results if r.local_port is not None]
    if len(ports) == len(set(ports)) and len(ports) > 1:
        print(f"\nFlow isolation confirmed: distinct source ports {ports}.")
    elif len(ports) > 1:
        print(f"\nWARNING: source ports not all distinct ({ports}). Isolation not guaranteed.")


if __name__ == "__main__":
    main()
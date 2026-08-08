"""
SEQUENTIAL / CORE (0-9)
  0. Health check                  - neutral baseline, no alerts, no enforcement
  1. Normal user traffic            - baseline requests
  2. User ID enumeration            - sequential ID access flags enumeration
  3. BOLA (user resource)           - enumeration + object-access violation on /users/{id}
  4. BOLA (order resource)          - same pattern on /orders/{id}
  5. Business flow rate abuse       - excessive hits to same object, rate-limited
  6. Login brute force              - repeated /login attempts, rate-limited
  7. Registration abuse             - repeated /register signups, rate-limited
  8. Shadow API probing             - hits undocumented routes
  9. BFLA (privilege escalation)    - identity baselined normal, then hits privileged path

EVASION (11-14) -- these intentionally probe blind spots. A "gap" result here
is not a test-harness bug -- it's the harness telling you what a smarter
attacker could get away with today.
  11. Slow-drip enumeration                - sequential IDs, paced outside rate window
  12. HTTP method fuzzing                  - TRACE / CONNECT / made-up verbs
  13. Missing-Authorization sweep          - protected paths hit with no token at all
  14. BFLA repeat-offender regression      - same token hits privileged path 5x;
      every hit should alert now that the one-shot latch is removed

KILL CHAIN (15)
  15. Multi-stage escalation - one identity: normal -> enumerate -> BOLA -> BFLA pivot,
      in one continuous session, validating cumulative risk stacking.

CONCURRENCY / STRESS (16-18) -- run in parallel threads, not sequential.
  16. Concurrent multi-attacker BOLA storm - N attackers hammering /orders at once
  17. Distributed botnet login brute force - M distinct identities vs /login at once
  18. Shared-identity race probe - K threads hammering the SAME token concurrently,
      checking the engine doesn't crash or silently drop detections under races
      (previous_object_ids / function_access_history / bola/rate histories are
      plain dicts with no locks in request_parser.py)

Run:
  python3 test.py                         # everything, once
  python3 test.py --skip-stress           # core + evasion only
  python3 test.py --skip-evasion          # core + stress only
  python3 test.py --repeat 3              # hammer the whole suite 3x back-to-back
  python3 test.py --stress-workers 12     # heavier concurrency
"""

from __future__ import annotations

import argparse
import html
import http.client
import json
import os
import random
import socket
import time
import webbrowser
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Optional


DEFAULT_HOST = "127.0.0.1"
DEFAULT_PORT = 8000
CONNECT_TIMEOUT = 5

REPORT_FILENAME = "test_report.html"

HEALTH_PATH = "/health"
LOGIN_PATH = "/login"
REGISTER_PATH = "/register"
USER_PATH_TEMPLATE = "/users/{id}"
OBJECT_PATH_TEMPLATE = "/orders/{id}"

SHADOW_PATHS = [
    "/v0/legacy/users",
    "/internal/debug",
    "/admin/export",
    "/api/v0/internal",
    "/debug/vars",
    "/manage/console",
    "/.env",
    "/actuator/health",
]

PRE_AUTH_IDENTITY_HEADER = "X-Client-Id"

HEADER_RISK_SCORE = "X-Risk-Score"
HEADER_ALERTS = "X-Alerts"
HEADER_ENFORCEMENT = "X-Enforcement"
DENY_STATUS_CODES = {401, 403, 429}


RUN_TAG = str(int(time.time()))


def tagged(token: str) -> str:
    return f"{token}-{RUN_TAG}"


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


def is_deny(status) -> bool:
    return status == "BLOCKED" or (isinstance(status, int) and status in DENY_STATUS_CODES)

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
    jitter: float = 0.0
    expect_alerts: list = field(default_factory=list)
    expect_enforcement: Optional[bool] = None
    note: str = ""  # printed under the scenario, e.g. flags a known evasion gap

    def build_requests(self) -> list[tuple[str, str, Optional[dict]]]:
        if self.ids is not None:
            return [(self.method, self.path_template.format(id=i), None) for i in self.ids]
        if self.path_sequence is not None:
            return [(self.method, p, None) for p in self.path_sequence]
        if self.body_seq is not None:
            return [(self.method, self.path, b) for b in self.body_seq]
        return [(self.method, self.path, None)] * self.count


def _shadow_requests(method: str = "GET"):
    return [(method, path, None) for path in SHADOW_PATHS]


@dataclass
class ScenarioResult:
    name: str
    local_port: Optional[int]
    alerts: set
    max_risk: Optional[int]
    enforcement_observed: bool
    deny_count: int
    total_requests: int
    log: list
    expect_alerts: list
    expect_enforcement: Optional[bool]
    note: str = ""


def run_scenario(scenario: Scenario, host: str, port: int) -> ScenarioResult:
    print(f"\n{'-' * 70}\nSCENARIO: {scenario.name}\n{'-' * 70}")

    flow = Flow(host, port)
    if flow.open_error:
        print(f"  Could not open flow: {flow.open_error}")
    else:
        print(f"  Flow opened -> local port {flow.local_port}")

    observed_alerts: set = set()
    max_risk_seen: Optional[int] = None
    deny_count = 0
    log = []

    requests = _shadow_requests() if scenario.name.startswith("8.") else scenario.build_requests()

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

        if is_deny(status):
            deny_count += 1

        extra = [x for x in [
            f"alerts={alert_val}" if alert_val else None,
            f"risk={risk_val}" if risk_val else None,
            f"enforcement={enf_val}" if enf_val else None,
            note,
        ] if x]
        print(f"    {method:4s} {path:22s} -> {status}" + (f"  [{', '.join(extra)}]" if extra else ""))
        log.append((path, status))

        sleep_for = scenario.pace + (random.uniform(0, scenario.jitter) if scenario.jitter else 0)
        time.sleep(sleep_for)

    flow.close()
    return ScenarioResult(
        name=scenario.name,
        local_port=flow.local_port,
        alerts=observed_alerts,
        max_risk=max_risk_seen,
        enforcement_observed=deny_count > 0,
        deny_count=deny_count,
        total_requests=len(requests),
        log=log,
        expect_alerts=scenario.expect_alerts,
        expect_enforcement=scenario.expect_enforcement,
        note=scenario.note,
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
            reasons.append("No X-Alerts header present -- enforcement is out-of-band (eBPF), inferred from status/enforcement instead.")

    if result.expect_enforcement is True and not result.enforcement_observed:
        ok = False
        reasons.append("Expected enforcement but every request succeeded.")
    if result.expect_enforcement is False and result.enforcement_observed:
        ok = False
        reasons.append("Unexpected deny/block on traffic that should have passed.")

    if not reasons:
        reasons.append("Observed behaviour matched expectations.")
    return ok, reasons

def core_scenarios() -> list[Scenario]:
    return [
        Scenario(
            name="0. Health check (neutral baseline)",
            path=HEALTH_PATH, count=3, pace=0.5,
            expect_alerts=[], expect_enforcement=False,
        ),
        Scenario(
            name="1. Normal user traffic (baseline)",
            path_template=USER_PATH_TEMPLATE, ids=[101, 102],
            token=tagged("Bearer Scenario1-Baseline"), pace=1.0,
            expect_alerts=[], expect_enforcement=False,
        ),
        Scenario(
            name="2. User ID enumeration",
            path_template=USER_PATH_TEMPLATE, ids=list(range(200, 210)),
            token=tagged("Bearer Scenario2-Enumeration"), pace=0.3,
            expect_alerts=["enum"], expect_enforcement=None,
        ),
        Scenario(
            name="3. BOLA attack (user resource)",
            path_template=USER_PATH_TEMPLATE, ids=list(range(300, 312)),
            token=tagged("Bearer Scenario3-BOLA"), pace=0.2,
            expect_alerts=["enum", "bola"], expect_enforcement=True,
        ),
        Scenario(
            name="4. BOLA attack (order resource)",
            path_template=OBJECT_PATH_TEMPLATE, ids=list(range(300, 312)),
            token=tagged("Bearer Scenario4-BOLA-Order"), pace=0.2,
            expect_alerts=["enum", "bola"], expect_enforcement=True,
        ),
        Scenario(
            name="5. Business flow rate abuse",
            path=USER_PATH_TEMPLATE.format(id=400),
            token=tagged("Bearer Scenario5-RateAbuse"), count=20, pace=0.05,
            expect_alerts=["rate"], expect_enforcement=True,
        ),
        Scenario(
            name="6. Login brute force",
            method="POST", path=LOGIN_PATH,
            client_id=tagged("Scenario6-BruteForce"),
            body_seq=[{"username": "admin", "password": f"guess{i}"} for i in range(15)],
            pace=0.1,
            expect_alerts=["rate"], expect_enforcement=True,
        ),
        Scenario(
            name="7. Registration abuse (bot signup)",
            method="POST", path=REGISTER_PATH,
            client_id=tagged("Scenario7-RegAbuse"),
            body_seq=[
                {"username": f"bot_user_{i}", "password": "Passw0rd!", "email": f"bot{i}@example.com"}
                for i in range(15)
            ],
            pace=0.1,
            expect_alerts=["rate"], expect_enforcement=True,
        ),
        Scenario(
            name="8. Shadow API probing (undocumented endpoints)",
            token=tagged("Bearer Scenario8-ShadowProbe"), pace=0.4,
            expect_alerts=["shadow"], expect_enforcement=None,
        ),
        Scenario(
            name="9. BFLA attack (privilege escalation)",
            path_sequence=["/users/101", "/admin/export", "/admin/export"],
            token=tagged("Bearer Scenario9-BFLA"), pace=0.3,
            expect_alerts=["broken function level authorization"], expect_enforcement=True,
        ),
    ]


def evasion_scenarios() -> list[Scenario]:
    return [
        Scenario(
            name="10. Non-sequential enumeration (step-by-2)",
            path_template=USER_PATH_TEMPLATE,
            ids=list(range(500, 522, 2)),  # 500,502,504... never triggers nums[i+1]==nums[i]+1
            token=tagged("Bearer Scenario10-StepEvasion"), pace=0.2,
            expect_alerts=["bola"], expect_enforcement=True,
            note=("check_enumeration() in validators.py only flags EXACT consecutive "
                  "IDs (n, n+1, n+2), so stepping by 2 evades that specific detector. "
                  "However, since this scenario carries a Bearer token, bola_engine.py "
                  "independently catches it via distinct-foreign-object-ID tracking "
                  "(order-agnostic), so the flow still gets enforced. No longer an "
                  "evasion scenario -- moved out of the EVASION block."),
        ),
        Scenario(
            name="11. EVASION: slow-drip sequential enumeration",
            path_template=USER_PATH_TEMPLATE, ids=list(range(600, 606)),
            token=tagged("Bearer Scenario11-SlowDrip"), pace=12.0,
            expect_alerts=["enum"], expect_enforcement=None,
            note=("Paced at 12s/request -- outside the rate-limiter's 10s window -- so "
                  "rate abuse should NOT fire. Enumeration has no pacing gate, so it "
                  "should still catch this. This scenario is slow by design; it's the "
                  "long one."),
        ),
        Scenario(
            name="12. HTTP method fuzzing",
            path_sequence=None,
            token=tagged("Bearer Scenario12-MethodFuzz"), pace=0.3,
            expect_alerts=[], expect_enforcement=False,
            note="Sends TRACE/CONNECT/custom verbs; each is only +20 risk alone, shouldn't cross the 60 block threshold by itself.",
        ),
        Scenario(
            name="13. Missing-Authorization sweep",
            path_sequence=["/users/900", "/orders/900", "/admin/x", "/manage/x", "/profile/900"],
            token=None, pace=0.3,
            expect_alerts=[], expect_enforcement=None,
            note="No Authorization header at all against every protected-path prefix in validators.py.",
        ),
        Scenario(
            name="14. BFLA repeat-offender regression (post-fix)",
            path_sequence=["/users/101", "/admin/export", "/admin/export", "/admin/export", "/admin/export"],
            token=tagged("Bearer Scenario14-BFLARepeat"), pace=0.3,
            expect_alerts=["broken function level authorization"], expect_enforcement=True,
            note=("Hits the privileged path 4 times after baselining normal. With the "
                  "one-shot latch removed, EVERY hit should alert -- check deny_count "
                  "in the summary, not just enforcement_observed."),
        ),
    ]


def _method_fuzz_requests():
    return [
        ("TRACE", "/users/101", None),
        ("CONNECT", "/users/101", None),
        ("FOO", "/users/101", None),
        ("PATCH", "/users/101", None),
    ]


def kill_chain_scenario() -> Scenario:
    seq = (
        ["/users/701", "/users/702"]                       # normal baseline
        + [f"/users/{i}" for i in range(710, 716)]          # enumeration window
        + [f"/orders/{i}" for i in range(720, 726)]         # pivot to BOLA on a second resource
        + ["/admin/export", "/admin/export"]                # pivot to BFLA
    )
    return Scenario(
        name="15. KILL CHAIN: recon -> enumerate -> BOLA -> BFLA pivot",
        path_sequence=seq,
        token=tagged("Bearer Scenario15-KillChain"), pace=0.25,
        expect_alerts=["enum", "bola", "broken function level authorization"],
        expect_enforcement=True,
        note="One continuous identity escalating through every detector in sequence -- validates cumulative risk stacking, not isolated triggers.",
    )

@dataclass
class StressResult:
    name: str
    worker_count: int
    total_requests: int
    deny_count: int
    errors: int
    elapsed_s: float
    ports_seen: list


def _worker_bola_storm(host, port, attacker_idx, base_id, request_count, pace):
    flow = Flow(host, port)
    token = tagged(f"Bearer Storm-Attacker-{attacker_idx}")
    denies = 0
    for i in range(request_count):
        status, _, _ = flow.request("GET", f"/orders/{base_id + i}", token=token)
        if is_deny(status):
            denies += 1
        time.sleep(pace)
    flow.close()
    return flow.local_port, denies, request_count


def run_bola_storm(host, port, workers: int) -> StressResult:
    print(f"\n{'-' * 70}\nSTRESS 16: Concurrent multi-attacker BOLA storm ({workers} attackers)\n{'-' * 70}")
    start = time.time()
    ports, denies, total, errors = [], 0, 0, 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(_worker_bola_storm, host, port, i, 800 + i * 20, 12, 0.15)
            for i in range(workers)
        ]
        for f in as_completed(futures):
            try:
                port_, d, n = f.result()
                ports.append(port_)
                denies += d
                total += n
            except Exception as e:
                errors += 1
                print(f"    worker error: {e}")
    elapsed = time.time() - start
    print(f"  {workers} attackers x 12 requests each finished in {elapsed:.2f}s -- {denies}/{total} requests denied.")
    return StressResult("16. Concurrent BOLA storm", workers, total, denies, errors, elapsed, ports)


def _worker_login_bot(host, port, bot_idx, request_count, pace):
    flow = Flow(host, port)
    client_id = tagged(f"Bot-{bot_idx}")
    denies = 0
    for i in range(request_count):
        status, _, _ = flow.request(
            "POST", LOGIN_PATH, client_id=client_id,
            body={"username": f"bot{bot_idx}", "password": f"try{i}"},
        )
        if is_deny(status):
            denies += 1
        time.sleep(pace)
    flow.close()
    return flow.local_port, denies, request_count


def run_login_botnet(host, port, workers: int) -> StressResult:
    print(f"\n{'-' * 70}\nSTRESS 17: Distributed botnet login brute force ({workers} bots)\n{'-' * 70}")
    start = time.time()
    ports, denies, total, errors = [], 0, 0, 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(_worker_login_bot, host, port, i, 12, 0.08)
            for i in range(workers)
        ]
        for f in as_completed(futures):
            try:
                port_, d, n = f.result()
                ports.append(port_)
                denies += d
                total += n
            except Exception as e:
                errors += 1
                print(f"    worker error: {e}")
    elapsed = time.time() - start
    per_identity_note = (
        "each bot is a distinct identity -- if rate limiting is correctly per-identity, "
        "every bot should independently cross the threshold and get denied, not just some."
    )
    print(f"  {workers} bots x 12 requests each finished in {elapsed:.2f}s -- {denies}/{total} requests denied.")
    print(f"  NOTE: {per_identity_note}")
    return StressResult("17. Distributed login botnet", workers, total, denies, errors, elapsed, ports)


def _worker_shared_identity(host, port, shared_token, worker_idx, id_start, request_count, pace):
    flow = Flow(host, port)
    denies = 0
    errors = 0
    for i in range(request_count):
        try:
            status, _, _ = flow.request("GET", f"/users/{id_start + worker_idx * 100 + i}", token=shared_token)
            if is_deny(status):
                denies += 1
        except Exception:
            errors += 1
        time.sleep(pace)
    flow.close()
    return flow.local_port, denies, request_count, errors


def run_shared_identity_race(host, port, workers: int) -> StressResult:
    print(f"\n{'-' * 70}\nSTRESS 18: Shared-identity race probe ({workers} threads, 1 token)\n{'-' * 70}")
    print("  NOTE: previous_object_ids / function_access_history / bola & rate histories "
          "are plain dicts with no locks in request_parser.py -- this checks the engine "
          "survives concurrent writers without crashing or silently losing detections.")
    shared_token = tagged("Bearer Scenario18-SharedRace")
    start = time.time()
    ports, denies, total, errors = [], 0, 0, 0
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = [
            pool.submit(_worker_shared_identity, host, port, shared_token, i, 900, 8, 0.05)
            for i in range(workers)
        ]
        for f in as_completed(futures):
            try:
                port_, d, n, e = f.result()
                ports.append(port_)
                denies += d
                total += n
                errors += e
            except Exception as e:
                errors += 1
                print(f"    worker error: {e}")
    elapsed = time.time() - start
    print(f"  {workers} threads x 8 requests each on ONE token finished in {elapsed:.2f}s "
          f"-- {denies}/{total} denied, {errors} client-side errors.")
    return StressResult("18. Shared-identity race probe", workers, total, denies, errors, elapsed, ports)

def run_core_and_evasion(host, port, include_evasion: bool) -> list[ScenarioResult]:
    results = []
    for scenario in core_scenarios():
        results.append(run_scenario(scenario, host, port))

    if include_evasion:
        for scenario in evasion_scenarios():
            if scenario.name.startswith("12."):
                # method fuzzing needs a custom request list (non-standard verbs)
                print(f"\n{'-' * 70}\nSCENARIO: {scenario.name}\n{'-' * 70}")
                if scenario.note:
                    print(f"  NOTE: {scenario.note}")
                flow = Flow(host, port)
                deny_count = 0
                for method, path, body in _method_fuzz_requests():
                    status, headers, note = flow.request(method, path, token=scenario.token)
                    if is_deny(status):
                        deny_count += 1
                    print(f"    {method:4s} {path:22s} -> {status}" + (f"  [{note}]" if note else ""))
                    time.sleep(scenario.pace)
                flow.close()
                results.append(ScenarioResult(
                    name=scenario.name, local_port=flow.local_port, alerts=set(), max_risk=None,
                    enforcement_observed=deny_count > 0, deny_count=deny_count, total_requests=4,
                    log=[], expect_alerts=scenario.expect_alerts,
                    expect_enforcement=scenario.expect_enforcement, note=scenario.note,
                ))
            else:
                results.append(run_scenario(scenario, host, port))

        results.append(run_scenario(kill_chain_scenario(), host, port))

    return results


def run_stress(host, port, workers: int) -> list[StressResult]:
    return [
        run_bola_storm(host, port, workers),
        run_login_botnet(host, port, workers),
        run_shared_identity_race(host, port, max(2, workers // 2)),
    ]


def print_summary(results: list[ScenarioResult], stress_results: list[StressResult]):
    print("\n" + "=" * 70)
    print("SUMMARY -- SEQUENTIAL SCENARIOS")
    print("=" * 70)

    all_pass = True
    gap_count = 0
    for result in results:
        ok, reasons = evaluate(result)
        is_evasion = "EVASION" in result.name
        all_pass = all_pass and (ok or is_evasion)
        label = "GAP (expected)" if (is_evasion and not ok) else ("PASS" if ok else "FAIL")
        if is_evasion and not ok:
            gap_count += 1

        print(f"\n{result.name}")
        print(f"  Flow local port : {result.local_port}")
        print(f"  Alerts observed : {sorted(result.alerts) or '(none / no header)'}")
        print(f"  Max risk seen   : {result.max_risk if result.max_risk is not None else '(no header)'}")
        print(f"  Deny count      : {result.deny_count}/{result.total_requests}")
        print(f"  Result          : {label}")
        for r in reasons:
            print(f"    - {r}")
        if result.note:
            print(f"    NOTE: {result.note}")

    if stress_results:
        print("\n" + "=" * 70)
        print("SUMMARY -- CONCURRENCY / STRESS")
        print("=" * 70)
        for sr in stress_results:
            print(f"\n{sr.name}")
            print(f"  Workers          : {sr.worker_count}")
            print(f"  Total requests   : {sr.total_requests}")
            print(f"  Denied           : {sr.deny_count}")
            print(f"  Client errors    : {sr.errors}")
            print(f"  Elapsed          : {sr.elapsed_s:.2f}s")
            distinct_ports = len(set(sr.ports_seen))
            print(f"  Flow isolation   : {distinct_ports}/{len(sr.ports_seen)} distinct source ports")
            if sr.errors > 0:
                print("  WARNING: client-side errors during concurrent run -- check for crashes/races on the server side too.")

    print("\n" + "-" * 70)
    print(f"OVERALL SEQUENTIAL: {'PASS' if all_pass else 'FAIL'}  (evasion gaps found: {gap_count})")
    print("-" * 70)

    ports = [r.local_port for r in results if r.local_port is not None]
    if len(ports) == len(set(ports)) and len(ports) > 1:
        print(f"\nFlow isolation confirmed: distinct source ports {ports}.")
    elif len(ports) > 1:
        print(f"\nWARNING: source ports not all distinct ({ports}). Isolation not guaranteed.")


# ---------------------------------------------------------------------------
# HTML report
#
# Purely additive: reads the same ScenarioResult / StressResult objects the
# terminal summary already prints, and renders them as a single self-contained
# HTML file (no external assets, works via plain file:// open). Terminal
# output above is untouched -- this is a second view onto the same data, not
# a replacement.
#
# Uses a FIXED filename (REPORT_FILENAME), so it always overwrites on a new
# invocation of test.py. But within one invocation, `--repeat N` collects
# every run into the SAME file as separate labeled sections, so repeated runs
# inside a single command never clobber each other -- only a brand new
# `python3 test.py` call replaces the file.
# ---------------------------------------------------------------------------

_STATUS_COLORS = {
    "PASS": ("#16a34a", "#dcfce7"),
    "FAIL": ("#dc2626", "#fee2e2"),
    "GAP (expected)": ("#d97706", "#fef3c7"),
}


def _scenario_label(result: ScenarioResult) -> tuple[str, bool]:
    ok, _ = evaluate(result)
    is_evasion = "EVASION" in result.name
    label = "GAP (expected)" if (is_evasion and not ok) else ("PASS" if ok else "FAIL")
    return label, (ok or is_evasion)


def _render_scenario_card(result: ScenarioResult) -> str:
    label, _ = _scenario_label(result)
    fg, bg = _STATUS_COLORS.get(label, ("#374151", "#e5e7eb"))
    _, reasons = evaluate(result)
    alerts = ", ".join(sorted(result.alerts)) if result.alerts else "(none / no header)"
    max_risk = result.max_risk if result.max_risk is not None else "(no header)"

    reasons_html = "".join(f"<li>{html.escape(r)}</li>" for r in reasons)
    note_html = (
        f'<div class="note"><strong>Note:</strong> {html.escape(result.note)}</div>'
        if result.note else ""
    )

    return f"""
    <div class="card">
      <div class="card-head">
        <span class="badge" style="color:{fg};background:{bg};">{html.escape(label)}</span>
        <span class="card-title">{html.escape(result.name)}</span>
      </div>
      <div class="card-body">
        <div class="stat-row">
          <div class="stat"><span class="stat-label">Local port</span><span class="stat-val">{result.local_port}</span></div>
          <div class="stat"><span class="stat-label">Max risk</span><span class="stat-val">{html.escape(str(max_risk))}</span></div>
          <div class="stat"><span class="stat-label">Deny count</span><span class="stat-val">{result.deny_count}/{result.total_requests}</span></div>
        </div>
        <div class="stat"><span class="stat-label">Alerts observed</span><span class="stat-val">{html.escape(alerts)}</span></div>
        <ul class="reasons">{reasons_html}</ul>
        {note_html}
      </div>
    </div>"""


def _render_stress_card(sr: StressResult) -> str:
    distinct_ports = len(set(sr.ports_seen))
    warn = (
        '<div class="note warn"><strong>Warning:</strong> client-side errors during '
        "concurrent run -- check for crashes/races on the server side too.</div>"
        if sr.errors > 0 else ""
    )
    return f"""
    <div class="card">
      <div class="card-head">
        <span class="badge" style="color:#374151;background:#e5e7eb;">STRESS</span>
        <span class="card-title">{html.escape(sr.name)}</span>
      </div>
      <div class="card-body">
        <div class="stat-row">
          <div class="stat"><span class="stat-label">Workers</span><span class="stat-val">{sr.worker_count}</span></div>
          <div class="stat"><span class="stat-label">Total requests</span><span class="stat-val">{sr.total_requests}</span></div>
          <div class="stat"><span class="stat-label">Denied</span><span class="stat-val">{sr.deny_count}</span></div>
          <div class="stat"><span class="stat-label">Client errors</span><span class="stat-val">{sr.errors}</span></div>
          <div class="stat"><span class="stat-label">Elapsed</span><span class="stat-val">{sr.elapsed_s:.2f}s</span></div>
          <div class="stat"><span class="stat-label">Flow isolation</span><span class="stat-val">{distinct_ports}/{len(sr.ports_seen)}</span></div>
        </div>
        {warn}
      </div>
    </div>"""


def _render_run_section(run_idx: int, run_tag: str, results: list[ScenarioResult],
                         stress_results: list[StressResult]) -> str:
    all_pass = True
    gap_count = 0
    for result in results:
        _, ok_or_evasion = _scenario_label(result)
        all_pass = all_pass and ok_or_evasion
        label, ok = _scenario_label(result)
        if label == "GAP (expected)":
            gap_count += 1

    overall_fg, overall_bg = ("#16a34a", "#dcfce7") if all_pass else ("#dc2626", "#fee2e2")
    overall_text = "PASS" if all_pass else "FAIL"

    scenario_cards = "".join(_render_scenario_card(r) for r in results)
    stress_cards = "".join(_render_stress_card(s) for s in stress_results)
    stress_section = (
        f'<h3 class="section-heading">Concurrency / Stress</h3><div class="grid">{stress_cards}</div>'
        if stress_results else ""
    )

    return f"""
  <section class="run">
    <div class="run-head">
      <h2>Run {run_idx} <span class="run-tag">tag={html.escape(run_tag)}</span></h2>
      <span class="overall-badge" style="color:{overall_fg};background:{overall_bg};">
        OVERALL: {overall_text} &middot; evasion gaps found: {gap_count}
      </span>
    </div>
    <h3 class="section-heading">Sequential Scenarios</h3>
    <div class="grid">{scenario_cards}</div>
    {stress_section}
  </section>"""


def generate_html_report(runs: list[tuple[int, str, list, list]], output_path: str) -> None:
    """runs: list of (run_idx, run_tag, results, stress_results)."""
    generated_at = time.strftime("%Y-%m-%d %H:%M:%S")
    sections = "".join(
        _render_run_section(run_idx, run_tag, results, stress_results)
        for run_idx, run_tag, results, stress_results in runs
    )

    doc = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>API-Sentinel Test Report</title>
<style>
  :root {{ color-scheme: light; }}
  * {{ box-sizing: border-box; }}
  body {{
    margin: 0; padding: 24px 32px 64px;
    background: #f5f6f8; color: #111827;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }}
  header.page-head {{ margin-bottom: 24px; }}
  header.page-head h1 {{ margin: 0 0 4px; font-size: 22px; }}
  header.page-head p {{ margin: 0; color: #6b7280; font-size: 13px; }}
  .run {{ margin-bottom: 40px; }}
  .run-head {{
    display: flex; align-items: center; justify-content: space-between;
    flex-wrap: wrap; gap: 12px;
    border-bottom: 2px solid #e5e7eb; padding-bottom: 10px; margin-bottom: 16px;
  }}
  .run-head h2 {{ margin: 0; font-size: 18px; }}
  .run-tag {{ font-weight: 400; font-size: 12px; color: #6b7280; margin-left: 8px; }}
  .overall-badge {{
    font-size: 12px; font-weight: 600; padding: 6px 12px; border-radius: 999px;
  }}
  .section-heading {{
    font-size: 13px; text-transform: uppercase; letter-spacing: 0.04em;
    color: #6b7280; margin: 18px 0 10px;
  }}
  .grid {{
    display: grid; grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
    gap: 14px;
  }}
  .card {{
    background: #ffffff; border: 1px solid #e5e7eb; border-radius: 10px;
    overflow: hidden;
  }}
  .card-head {{
    display: flex; align-items: center; gap: 10px;
    padding: 12px 14px; border-bottom: 1px solid #f0f1f3;
  }}
  .badge {{
    font-size: 11px; font-weight: 700; padding: 3px 8px; border-radius: 6px;
    white-space: nowrap;
  }}
  .card-title {{ font-size: 13px; font-weight: 600; }}
  .card-body {{ padding: 12px 14px; }}
  .stat-row {{ display: flex; flex-wrap: wrap; gap: 16px; margin-bottom: 8px; }}
  .stat {{ display: flex; flex-direction: column; margin-bottom: 8px; }}
  .stat-label {{ font-size: 10px; text-transform: uppercase; color: #9ca3af; letter-spacing: 0.03em; }}
  .stat-val {{ font-size: 13px; font-weight: 600; word-break: break-word; }}
  ul.reasons {{ margin: 6px 0 0; padding-left: 18px; font-size: 12px; color: #374151; }}
  ul.reasons li {{ margin-bottom: 2px; }}
  .note {{
    margin-top: 10px; padding: 8px 10px; border-radius: 6px;
    background: #f3f4f6; border-left: 3px solid #9ca3af;
    font-size: 12px; color: #4b5563; line-height: 1.4;
  }}
  .note.warn {{ background: #fef3c7; border-left-color: #d97706; color: #78350f; }}
</style>
</head>
<body>
  <header class="page-head">
    <h1>API-Sentinel Test Report</h1>
    <p>Generated {generated_at}</p>
  </header>
  {sections}
</body>
</html>"""

    with open(output_path, "w", encoding="utf-8") as f:
        f.write(doc)


def main():
    parser = argparse.ArgumentParser(description="API-Sentinel test harness -- core + evasion + stress")
    parser.add_argument("--host", default=DEFAULT_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_PORT)
    parser.add_argument("--skip-evasion", action="store_true", help="run only the original 0-9 core scenarios")
    parser.add_argument("--skip-stress", action="store_true", help="skip the concurrency/stress section")
    parser.add_argument("--stress-workers", type=int, default=6, help="parallel attackers/bots for stress scenarios")
    parser.add_argument("--repeat", type=int, default=1, help="run the whole suite N times back-to-back")
    parser.add_argument("--no-html-report", action="store_true", help="skip writing test_report.html")
    parser.add_argument("--no-open-report", action="store_true", help="write the report but don't auto-open it in a browser")
    args = parser.parse_args()

    html_runs = []  # (run_idx, run_tag, results, stress_results) -- collected across --repeat

    for run_idx in range(1, args.repeat + 1):
        global RUN_TAG
        RUN_TAG = f"{int(time.time())}-r{run_idx}"

        print("=" * 70)
        print(f"API-Sentinel TEST  (run {run_idx}/{args.repeat}, tag={RUN_TAG})")
        print("=" * 70)

        results = run_core_and_evasion(args.host, args.port, include_evasion=not args.skip_evasion)
        stress_results = [] if args.skip_stress else run_stress(args.host, args.port, args.stress_workers)

        print_summary(results, stress_results)
        html_runs.append((run_idx, RUN_TAG, results, stress_results))

    if not args.no_html_report:
        report_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), REPORT_FILENAME)
        generate_html_report(html_runs, report_path)
        print(f"\nHTML report written -> {report_path}")
        print(f"(fixed filename -- overwritten on the next `python3 test.py` invocation; "
              f"all {len(html_runs)} run(s) from this invocation are in this one file)")
        if not args.no_open_report:
            try:
                webbrowser.open(f"file://{report_path}")
                print("Opened report in your default browser.")
            except Exception as exc:
                print(f"(Could not auto-open browser: {exc}. Open the file above manually "
                      f"by double-clicking it in your file explorer -- NOT inside VS Code, "
                      f"which only shows raw HTML text.)")


if __name__ == "__main__":
    main()
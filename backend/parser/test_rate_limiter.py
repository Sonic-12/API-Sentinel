import http.client
import socket
import time

HOST = "127.0.0.1"
PORT = 8000
CONNECT_TIMEOUT = 5


RESET_URL_PATH = None  


HEADER_RISK_SCORE = "X-Risk-Score"
HEADER_ALERTS = "X-Alerts"
HEADER_ENFORCEMENT = "X-Enforcement"

DENY_STATUS_CODES = {401, 403, 429}


class Flow:
    """One persistent TCP connection = one enforcement-relevant flow."""

    def __init__(self, host=HOST, port=PORT, timeout=CONNECT_TIMEOUT):
        self.conn = http.client.HTTPConnection(host, port, timeout=timeout)
        self.local_port = None
        self.open_error = None
        try:
            self.conn.connect()
            self.local_port = self.conn.sock.getsockname()[1]
        except OSError as e:
            self.open_error = str(e)

    def get(self, path, token):
        if self.open_error:
            return "BLOCKED", {}, f"flow never opened: {self.open_error}"

        headers = {
            "Authorization": token,
            "Accept": "application/json",
            "Connection": "keep-alive",
        }
        try:
            self.conn.request("GET", path, headers=headers)
            resp = self.conn.getresponse()
            resp.read()
            return resp.status, dict(resp.getheaders()), None
        except (
            ConnectionResetError, ConnectionAbortedError, BrokenPipeError,
            http.client.RemoteDisconnected, socket.timeout, OSError,
        ) as e:
            return "BLOCKED", {}, str(e)
        except Exception as e:
            return "ERROR", {}, str(e)

    def close(self):
        try:
            self.conn.close()
        except Exception:
            pass


def best_effort_reset():
    if not RESET_URL_PATH:
        return
    try:
        conn = http.client.HTTPConnection(HOST, PORT, timeout=CONNECT_TIMEOUT)
        conn.request("POST", RESET_URL_PATH)
        conn.getresponse().read()
        conn.close()
    except Exception:
        pass


def run_scenario(name, token, request_plan, pace_seconds):
    print(f"\n{'-' * 70}\nSCENARIO: {name}\n{'-' * 70}")

    best_effort_reset()
    flow = Flow()
    if flow.open_error:
        print(f"  Could not open flow: {flow.open_error}")
    else:
        print(f"  Flow opened -> local port {flow.local_port}")

    observed_alerts = set()
    max_risk_seen = None
    saw_deny = False
    log = []

    for path in request_plan:
        status, headers, note = flow.get(path, token)

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
        print(f"    {path:20s} -> {status}" + (f"  [{', '.join(extra)}]" if extra else ""))
        log.append((path, status))
        time.sleep(pace_seconds)

    flow.close()
    return {
        "name": name, "local_port": flow.local_port, "alerts": observed_alerts,
        "max_risk": max_risk_seen, "enforcement_observed": saw_deny, "log": log,
    }


def scenario_1_baseline():
    return run_scenario("1. Normal traffic (baseline)", "Bearer Scenario1-Baseline",
                         ["/users/101", "/users/102"], 1.0)


def scenario_2_enumeration():
    return run_scenario("2. User ID enumeration", "Bearer Scenario2-Enumeration",
                         [f"/users/{uid}" for uid in range(200, 210)], 0.3)


def scenario_3_bola():
    return run_scenario("3. BOLA attack", "Bearer Scenario3-BOLA",
                         [f"/users/{uid}" for uid in range(300, 312)], 0.2)


def scenario_4_rate_abuse():
    return run_scenario("4. Business flow rate abuse", "Bearer Scenario4-RateAbuse",
                         ["/users/400"] * 20, 0.05)


def evaluate(result, expect_alerts_any, expect_enforcement):
    reasons = []
    ok = True

    if expect_alerts_any:
        if result["alerts"]:
            for needle in expect_alerts_any:
                if not any(needle in a for a in result["alerts"]):
                    ok = False
                    reasons.append(f"Expected alert containing '{needle}', got {sorted(result['alerts'])}.")
        else:
            reasons.append("No X-Alerts header present -- only inferred from status/enforcement.")

    if expect_enforcement is True and not result["enforcement_observed"]:
        ok = False
        reasons.append("Expected enforcement but every request succeeded.")
    if expect_enforcement is False and result["enforcement_observed"]:
        ok = False
        reasons.append("Unexpected deny/block on traffic that should have passed.")

    if not reasons:
        reasons.append("Observed behaviour matched expectations.")
    return ok, reasons


def main():
    print("=" * 70)
    print("API-Sentinel - Week 3 Analytics Integration Test")
    print("=" * 70)

    r1 = scenario_1_baseline()
    r2 = scenario_2_enumeration()
    r3 = scenario_3_bola()
    r4 = scenario_4_rate_abuse()

    checks = [
        (r1, [], False),
        (r2, ["enum"], None),
        (r3, ["enum", "bola"], True),
        (r4, ["rate"], True),
    ]

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)

    all_pass = True
    for result, expect_alerts, expect_enforcement in checks:
        ok, reasons = evaluate(result, expect_alerts, expect_enforcement)
        all_pass = all_pass and ok
        print(f"\n{result['name']}")
        print(f"  Flow local port : {result['local_port']}")
        print(f"  Alerts observed : {sorted(result['alerts']) or '(none / no header)'}")
        print(f"  Max risk seen   : {result['max_risk'] if result['max_risk'] is not None else '(no header)'}")
        print(f"  Enforcement seen: {result['enforcement_observed']}")
        print(f"  Result          : {'PASS' if ok else 'FAIL'}")
        for r in reasons:
            print(f"    - {r}")

    print("\n" + "-" * 70)
    print(f"OVERALL: {'PASS' if all_pass else 'FAIL'}")
    print("-" * 70)

    ports = [r["local_port"] for r in (r1, r2, r3, r4) if r["local_port"] is not None]
    if len(ports) == len(set(ports)) and len(ports) > 1:
        print(f"\nFlow isolation confirmed: distinct source ports {ports}.")
    elif len(ports) > 1:
        print(f"\nWARNING: source ports not all distinct ({ports}). Isolation not guaranteed.")


if __name__ == "__main__":
    main()
# Python Parser

Processes the HTTP events captured by the eBPF/Rust layer — the second stage of the pipeline.

- Reads JSON events printed by the Rust userspace app (stdout).
- Reconstructs the original HTTP request.
- Runs security validation against it.
- Records suspicious activity and enforces on high-risk flows.

Split into single-responsibility modules, listed below in order.

---

## integration.py

- Entry point of the parser.
- Reads one JSON event per line from stdin (piped from the Rust app).
- Ignores anything that isn't a request event, or has no payload.
- Hands the hex payload to `decoder.py`, then the decoded text to `request_parser.py`.
- Coordinates the rest of the modules; contains no detection logic itself.

---

## decoder.py

- Converts the hex-encoded payload into plain UTF-8 HTTP text.
- Output is the complete request: request line, headers, body — ready for `request_parser.py`.

---

## request_parser.py

- Parses the decoded HTTP text into method, path, HTTP version, headers, query parameters, and body.
- Resolves a per-request **identity**: `Authorization` header → `X-Client-Id` header → client IP → `"unknown"`. Every detection module below uses this same identity, so a single client is tracked consistently across all of them.
- Builds a `ParsedRequest` object (`models.py`) and runs, in order:
  1. `check_http_method`
  2. `check_authorization`
  3. `check_sensitive_path`
  4. `check_enumeration`
  5. `check_function_level_authorization`
  6. `bola_engine.evaluate`
  7. `rate_limiter.evaluate`
- After all checks run, logs the request (if flagged) and calls `enforcer.block_flow()` if `risk_score >= 60`.
- Shared state used by these checks (`previous_object_ids`, `function_access_history`, and the internal state inside `bola_engine` / `rate_limiter`) is protected by locks, so concurrent requests from the same identity can't race and silently drop a detection.

---

## models.py

- Defines `ParsedRequest`, the single structured object passed between every module instead of loose variables.
- Holds method, path, headers, query parameters, body, `risk_score`, and `alerts`.
- One shared model keeps every module working against the same representation of a request.

---

## validators.py

Runs the core rule-based checks against a `ParsedRequest`:

| Check | Detects |
|---|---|
| `check_http_method` | Invalid/unexpected HTTP verbs (TRACE, CONNECT, custom) |
| `check_authorization` | Missing `Authorization` header on protected paths |
| `check_sensitive_path` | Access to sensitive path prefixes (`/admin`, `/debug`, etc.) |
| `check_enumeration` | Exact consecutive object-ID access (`n, n+1, n+2`) — a narrower, pattern-based signal that overlaps with `bola_engine.py` below |
| `check_function_level_authorization` | Broken Function Level Authorization (BFLA) — an identity that previously only hit standard endpoints suddenly hitting a privileged one |

Each check adds risk and an alert to the `ParsedRequest` when it fires.

---

## bola_engine.py

- Implements the Broken Object Level Authorization (BOLA) heuristic.
- Baselines the first object ID an identity accesses as "their own," then tracks how many **distinct foreign** object IDs that same identity touches afterward — regardless of order or step pattern.
- Once the foreign-object count crosses a threshold, raises a BOLA alert and adds risk (scaling with how far past the threshold the count goes).
- Because it's order-agnostic, it independently catches enumeration patterns that evade `check_enumeration()`'s strict consecutive-ID check (e.g. stepping by 2, or random-order access), as long as the identity is resolvable.

---

## rate_limiter.py

- Tracks request counts per identity, per endpoint template, in a sliding time window.
- Flags bot-style abuse: login brute force, registration spam, repeated hits to the same business-flow endpoint.
- Independent of `bola_engine.py` and `validators.py` — a flow can trip rate limiting without tripping enumeration/BOLA, and vice versa.

---

## masking.py

- Redacts PII before anything is logged or displayed: Authorization tokens and other sensitive headers are hashed/masked, fields like passwords or card numbers are fully redacted, and fields like email/username are partially masked.
- Runs *before* `loger.py` writes anything to disk — nothing sensitive is ever persisted unmasked.

---

## enforcer.py

- Fires when a request's `risk_score` crosses the block threshold (`60`).
- Connects to the Rust app's Unix control socket (`/tmp/api-sentinel.sock`) and sends the flow's `saddr/daddr/sport/dport` plus a TTL.
- The Rust app updates the pinned eBPF blocklist map; the kernel then drops that flow's packets for the TTL duration. This is the enforcement half of the loop described in (1).
---

## loger.py

- Writes flagged requests (any request with one or more alerts) to `alerts.log` as JSON.
- Stores the already-masked request details, the generated alerts, and the risk score.
- Provides a persistent record for later analysis, debugging, or incident investigation.

---

## Overall Operation

1. eBPF/Rust layer captures a request and prints a JSON event to stdout.
2. `integration.py` reads that event and passes the hex payload to `decoder.py`.
3. `decoder.py` decodes it into plain HTTP text.
4. `request_parser.py` parses that text into a `ParsedRequest` (`models.py`), resolves the request's identity, and runs `validators.py`, `bola_engine.py`, and `rate_limiter.py` against it.
5. If any check fires, `masking.py` redacts sensitive fields and `loger.py` writes the result to `alerts.log`.
6. If the accumulated `risk_score` crosses the block threshold, `enforcer.py` requests kernel-level enforcement for that flow.
7. The same structured request is also printed onward and picked up by (3).

Each module has a single responsibility, keeping the pipeline modular, testable, and easy to extend.
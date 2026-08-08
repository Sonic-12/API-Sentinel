# Traffic Interception (eBPF)

Kernel-level capture of HTTP traffic — the first stage of the API-Sentinel pipeline.

---

## Overview

- Captures HTTP requests and responses directly from the Linux kernel, not from application logs or middleware.
- Implemented as an eBPF program (C) plus a Rust userspace application.
- The eBPF program captures raw payloads in-kernel; the Rust app receives them via a Ring Buffer and converts them into structured JSON.
- Also owns the enforcement side: a pinned BPF map lets the kernel drop packets for a flow on command, independent of this capture path.

---

## Status

- Implemented and tested on Ubuntu 26.04 LTS.
- Captures both incoming requests and outgoing responses for the FastAPI/Uvicorn target app.
- Each event carries: timestamp, process ID, process name, connection ID, payload length, traffic direction, and raw payload.

---

## Why eBPF

- Application logs only record what the app explicitly chooses to log.
- eBPF observes network activity independently of application logic, at very low overhead.
- No kernel modification and no traditional kernel module required — eBPF programs are verified and run safely inside the kernel.

---

## kprobes

Dynamic kernel instrumentation used to run eBPF code whenever a target kernel function is called. This project hooks two:

- **`tcp_recvmsg`** — captures incoming HTTP requests.
  - A kprobe (entry) + kretprobe (return) pair is used, since the userspace buffer is only populated after the kernel completes the receive.
  - Entry probe stores context; return probe reads the completed payload.
- **`tcp_sendmsg_locked`** — captures outgoing HTTP responses.
  - Read directly on entry, since the response buffer already exists before transmission.

---

## Ring Buffer

- Communication channel between kernel and userspace.
- Every captured request/response is written here by the eBPF program; the Rust app polls continuously and receives each event with no repeated kernel queries.

---

## Enforcement Path (Blocklist Map)

- A second BPF map, pinned at `/sys/fs/bpf/api_sentinel_blocklist`, is checked per packet alongside the normal capture path.
- If the current flow (`saddr:sport <-> daddr:dport`) is present and not yet expired, the kernel drops the packet.
- The Rust app is the only writer to this map. It listens on a Unix control socket (`/tmp/api-sentinel.sock`); the Python parser's `enforcer.py` connects to that socket and sends `{saddr, daddr, sport, dport, ttl_ms}` when a request's risk score crosses the block threshold.
- This makes the capture path (kernel → Rust → parser) and the enforcement path (parser → Rust → kernel) two halves of the same loop, both owned by this module.

---

## libbpf / libbpf-rs

- **libbpf** — official userspace library for loading eBPF programs, creating kernel maps, and attaching probes.
- **libbpf-rs** — Rust bindings over libbpf, used so the userspace app can drive all of the above with native Rust APIs.

---

## Rust Userspace Application

Responsibilities:
- Load the eBPF program and attach all kprobes.
- Create and poll the Ring Buffer.
- Convert binary events into structured JSON and print one line per event to stdout.
- Pin the blocklist map and run the control socket that accepts block commands from the parser.

---

## Event Structure

Each captured event contains:

| Field | Description |
|---|---|
| Timestamp | When the event was captured |
| Connection ID | Ties requests and responses on the same TCP connection together |
| Process ID / Name | Source process |
| Traffic Direction | `request` or `response` |
| Payload Length | Size of the captured payload |
| Raw Payload | Hex-encoded HTTP data |

---

## Output

- One structured JSON record per captured request/response, printed to stdout.
- Payload is hex-encoded, preserving the original bytes exactly as observed in-kernel.
- This stdout stream is what `integration.py` (Python parser) consumes.
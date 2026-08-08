# API-Sentinel

End-to-end flow from a raw client request to what renders on the React dashboard.

---

## Simple Overview

```mermaid
flowchart TD
    Client["Client"] --> FastAPI["FastAPI App"]
    FastAPI --> eBPF["eBPF / Kernel + Rust"]
    eBPF --> Parser["Python Parser"]
    Parser --> Discovery["Discovery Pipeline"]
    Discovery --> DashboardAPI["Dashboard API"]
    DashboardAPI --> React["React Dashboard"]
    Parser -.->|"enforcement"| eBPF
```

- Correct order: **Client → FastAPI App → eBPF/Kernel+Rust → Parser → Discovery → Dashboard API → React**.
- The dotted line is the one loop-back in the system: the parser can tell the eBPF layer to block a flow.

---

## Detailed Diagram

```mermaid
flowchart TD
    Client["Client"] -->|"HTTP request"| App["Mock Target App\n(FastAPI/Uvicorn — app/main.py)"]

    subgraph Kernel["Linux Kernel"]
        eBPF["eBPF Program\n(kprobes: tcp_recvmsg, tcp_sendmsg_locked)"]
        Blocklist["Pinned BPF Map\n(blocklist)"]
        eBPF -->|"checked per packet"| Blocklist
    end

    App -.->|"TCP send/recv intercepted"| eBPF
    eBPF -->|"Ring Buffer"| Rust["Rust Userspace App\n(libbpf-rs)"]

    Rust -->|"JSON event per request/response\n(stdout)"| Parser["Python Parser\n(integration.py → decoder.py → request_parser.py)"]
    Rust <-->|"Unix control socket\n/tmp/api-sentinel.sock"| Enforcer["enforcer.py"]

    Parser --> Validators["validators.py\n(auth, sensitive path, enumeration, BFLA)"]
    Parser --> Bola["bola_engine.py\n(BOLA heuristic)"]
    Parser --> Rate["rate_limiter.py\n(bot / rate abuse)"]
    Validators --> Risk["risk_score + alerts\n(models.py)"]
    Bola --> Risk
    Rate --> Risk

    Risk -->|"risk_score >= 60"| Enforcer
    Risk --> Masking["masking.py\n(PII redaction)"]
    Masking --> Logger["loger.py → alerts.log"]

    Parser -->|"structured JSON\n(stdout)"| Discovery["Discovery Pipeline\n(discovery/pipeline.py)"]
    Discovery --> Normalizer["normalizer.py"]
    Discovery --> Inventory["inventory.py"]
    Discovery --> AccessLog["access_log.py"]
    Inventory --> OpenAPI["openapi_generator.py"]
    OpenAPI --> Comparator["comparator.py\n(shadow API diff)"]
    Comparator --> ReportWriter["report_writer.py"]
    AccessLog --> ReportWriter
    ReportWriter -->|"atomic write"| ReportFile["discovery_report.json"]

    ReportFile --> DashboardAPI["Dashboard API\n(FastAPI — dashboard_api/main.py)"]
    Logger -.->|"masked logs"| DashboardAPI
    DashboardAPI -->|"REST + SSE\n/api/*"| React["React Dashboard\n(Vite — frontend/src)"]
```

- Full description of what every module in this diagram does lives in its own doc, linked above — not repeated here.

---

## Key Design Points

- Traffic is only observed; enforcement is a deliberate, narrow action (single flow, time-limited TTL) triggered only past the risk threshold.
- The `discovery_report.json` decouples the detection pipeline from the dashboard; the API layer never needs to know how detection works internally.
- Enumeration, BOLA, BFLA, and rate abuse are independent detectors that can and do overlap (e.g. `bola_engine.py` also catches non-sequential ID enumeration that `check_enumeration()` alone would miss).
- Masking happens before logging, not after.
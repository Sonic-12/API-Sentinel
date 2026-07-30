# Project 1 – "API-Sentinel": Runtime BOLA & Shadow API Detection Engine

**Domain:** API Security & Zero-Trust Architecture

## Problem Statement

Modern architectures rely heavily on APIs, but they are incredibly difficult to secure. The OWASP API Security Top 10 for 2025/2026 highlights that traditional Web Application Firewalls (WAFs) consistently miss complex business logic attacks like Broken Object Level Authorization (BOLA) and completely ignore undocumented "Shadow APIs."

## Use Case

A massive e-commerce platform deploys API-Sentinel. Utilizing **eBPF (Extended Berkeley Packet Filter)** at the Linux kernel level — built with **libbpf** — it silently monitors all internal East-West and external API traffic without impacting developer velocity. The engine automatically generates an inventory of all active endpoints, instantly flagging deprecated "Zombie APIs." When an attacker attempts a BOLA attack — manipulating an API endpoint property to access another user's billing data — API-Sentinel detects the behavioral anomaly in real time, blocking the transaction at the execution level.

## Key Modules

- **Kernel-Level Sniffer (eBPF & libbpf):** Intercepts raw API traffic at the operating system level using libbpf-based programs (tracepoints/kprobes + ring buffers), giving deep, execution-level visibility without requiring code changes to the microservices.
- **Shadow API Discovery Engine:** Compares live traffic against official OpenAPI/Swagger contracts, actively discovering undocumented or rogue endpoints.
- **Behavioral Authorization AI (Python):** Analyzes request patterns to establish normal behavior, dynamically detecting BOLA and Broken Function Level Authorization (BFLA) attempts.
- **Threat Dashboard (React):** Visualizes the API attack surface, highlighting vulnerable endpoints and mapping active attacks to the OWASP API Top 10 framework.

---

## Development Roadmap (Phase-wise)

### Phase 1 — Foundation & Environment Setup
Build the conceptual and technical groundwork before writing any capture code.

- Study API security fundamentals: the OWASP API Security Top 10, BOLA, Shadow APIs, and Zero-Trust Architecture principles.
- Review reference material (OWASP API Security Top 10 documentation, this project document) and relevant talks on API security and API gateways.
- Learn core Linux networking concepts needed for kernel-level capture: TCP/IP, HTTP, sockets, and the kernel-vs-userspace boundary. Practice with `curl`, `netstat`, `ss`, and `tcpdump` to see how a request actually reaches the kernel.
- Get comfortable with the language used for the eBPF userspace/loader components (structs, functions, ownership/borrowing if using Rust bindings, or C fundamentals if writing libbpf directly), including error handling, modules, and collections — build a small CLI tool as practice.
- Stand up a basic FastAPI service exposing sample endpoints (e.g., `GET /users`, `GET /products`, `POST /login`, `GET /orders/{id}`) to act as the mock target application.
- **Deliverable:** Architecture diagram of the full system, plus a running mock API server.

### Phase 2 — eBPF Capture Engine & Mock Microservice
Get raw packet/event capture working against a realistic target.

- Set up the eBPF toolchain: LLVM, Clang, `bpftool`, and **libbpf** (with `libbpf-bootstrap` or `libbpf-rs` if using Rust for the userspace loader). Study libbpf's architecture — BPF object skeletons, program loading/verification, and CO-RE (Compile Once – Run Everywhere).
- Learn the core eBPF primitives: tracepoints, kprobes, BPF maps, and ring buffers. Review example libbpf projects and community reference material (e.g., eBPF Summit talks) before writing custom code.
- Build out a fuller mock e-commerce API (`/login`, `/products`, `/orders`, `/cart`, `/payment`) with an auto-generated Swagger/OpenAPI spec to serve as the "ground truth" contract.
- Write the first libbpf-based eBPF program to attach to kernel tracepoints/kprobes and passively capture connection metadata — PID, source IP, destination IP, and port — printing results to console.
- Extend the program to capture HTTP-level traffic and export captured events as JSON via a BPF ring buffer to userspace.
- **Deliverable:** A working libbpf-based packet monitor producing structured JSON event output.

### Phase 3 — Traffic Parser
Turn raw kernel-level events into structured, queryable API request data.

- Build a Python service that ingests the JSON events emitted by the libbpf capture engine and stores timestamp, IP, and payload data.
- Parse out HTTP semantics: method (GET/POST/PUT/DELETE), endpoint path, headers, and body.
- Persist parsed data into a relational store (SQLite or PostgreSQL) with tables for requests, endpoints, and users.
- Expose a FastAPI backend over this data with endpoints such as `GET /traffic`, `GET /latest`, and `GET /stats`.
- Validate the pipeline end-to-end using Postman/`curl` by generating a batch of sample requests (e.g., 100 requests) and confirming they're captured and queryable.
- **Deliverable:** A populated, queryable traffic database backed by real captured requests.

### Phase 4 — Security Analytics (Threat Detection Engine)
Layer detection logic on top of the parsed traffic data.

- **Shadow API Detection:** Compare observed endpoints against the official Swagger/OpenAPI contract; flag and alert on any endpoint not present in the spec.
- **Zombie API Detection:** Identify traffic hitting endpoints marked deprecated in the spec but still receiving live requests, and alert accordingly.
- **BOLA Detection:** Track (UserID, ObjectID) ownership pairs and check each request against expected ownership; alert when a user accesses an object they don't own.
- **Behavior Analysis:** Add anomaly detection on top of the rule-based checks — an Isolation Forest model, or a simpler rule engine as a lighter-weight alternative.
- Validate detection by simulating an attack (User A requesting User B's order) and confirming the engine correctly flags it.
- **Deliverable:** A functioning threat detection engine covering Shadow API, Zombie API, and BOLA detection.

### Phase 5 — React Dashboard
Give the detection engine a usable interface for security teams.

- Scaffold a React project with Axios (API calls), Material UI (components), and Chart.js (visualizations).
- Build summary dashboard cards for total requests, active alerts, tracked users, and discovered shadow APIs.
- Add a traffic table showing method, endpoint, source IP, and timestamp per request.
- Build a dedicated threats page listing BOLA, Shadow API, and Zombie API detections.
- Map each detected threat category explicitly to its corresponding OWASP API Security Top 10 category (e.g., BOLA → API1).
- **Deliverable:** A working, end-to-end security dashboard wired to the backend.

### Phase 6 — Runtime Protection & Finalization
Move from passive monitoring to active enforcement, then package the project for presentation.

- Implement rate limiting (e.g., 100 requests/min per user or endpoint) with automatic blocking on violation.
- Add PII masking so sensitive fields are stripped/redacted before data reaches storage or the dashboard.
- Upgrade the libbpf program from passive observation to active enforcement — dropping packets that violate access-control rules (or simulating blocking at the application layer if kernel-level enforcement is out of scope).
- Run performance testing to measure the latency overhead the eBPF sidecar adds to API requests, and confirm it stays within target bounds.
- Finalize documentation and deliverables: architecture diagram, data-flow diagram, presentation deck, demo video, GitHub repository with README, and a testing report.

---

## Suggested Delivery Milestones

1. **Minimum Viable Product** *(Phases 1–3)*: Mock API + libbpf-based eBPF event capture + Python parser + traffic database.
2. **Core Security Features** *(Phases 4–5)*: Shadow API detection, Zombie API detection, BOLA detection, and the React dashboard.
3. **Advanced Features** *(Phase 6)*: Rate limiting, PII masking, runtime blocking (or simulated blocking if kernel enforcement is descoped), performance testing, and final documentation.

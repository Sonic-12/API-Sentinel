# System Design

## Objective

The objective of API-Sentinel is to monitor HTTP/REST API traffic with minimal impact on application performance by leveraging Linux eBPF technology.

---

## Data Flow

The expected flow of data within the system is shown below.

```
Client
    │
HTTP Request
    │
    ▼
FastAPI Mock Microservice
    │
Generated Network Traffic
    │
    ▼
eBPF Program (Rust)
    │
Captured Events
    │
    ▼
Userspace Application
    │
Processed Events
    │
    ▼
Python Analytics Engine
    │
Security Analysis
    │
    ▼
Dashboard
```

---

## Module Responsibilities

### FastAPI Backend

Generates API traffic for testing and development.

### eBPF Module

Captures HTTP network events from the Linux kernel without modifying the application.

### Userspace Application

Receives events from the eBPF program and forwards them for processing.

### Analytics Engine

Processes captured events into meaningful API information for further analysis.

### Dashboard

Displays API activity and security insights.

---

## Design Principles

- Modular architecture
- Passive traffic monitoring
- Low performance overhead
- Independent components
- Easy future scalability
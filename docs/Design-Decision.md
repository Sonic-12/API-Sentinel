# Design Decisions

This document explains the technical decisions taken during the development of API-Sentinel.

---

## Why FastAPI?

FastAPI is lightweight, easy to develop with, and automatically generates OpenAPI documentation. It provides an ideal environment for generating predictable REST API traffic during development.

---

## Why Rust?

Rust offers memory safety, high performance, and excellent compatibility with Linux eBPF development.

---

## Why eBPF?

eBPF enables passive traffic monitoring directly inside the Linux kernel without modifying the target application.

---

## Why Ubuntu?

Ubuntu provides stable support for Linux kernel development tools, Rust, and eBPF libraries.

---

## Why Git Branches?

Each developer works independently on a feature branch to reduce merge conflicts and maintain a clean development history.

---

## Why a Mock Microservice?

The FastAPI application serves as a controlled environment for generating API traffic before integrating with production workloads.

---

## Future Technical Decisions

Future development may include:

- PostgreSQL integration
- Real-time monitoring dashboard
- API behavior analysis
- Shadow API detection
- OWASP API Top 10 detection
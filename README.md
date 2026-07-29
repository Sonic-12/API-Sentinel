# API-Sentinel

API-Sentinel is an enterprise-inspired API Security platform designed to monitor, analyze, and secure HTTP/REST API traffic using eBPF and Rust. The project provides real-time API traffic visibility by capturing HTTP requests at the kernel level and processing them through a Python-based analysis engine. It serves as a foundation for detecting API security threats such as Broken Object Level Authorization (BOLA), Broken Function Level Authorization (BFLA), and Shadow APIs.

> **Project Status:** Under Development

---

## Project Objectives

- Monitor HTTP/REST API traffic at the kernel level using eBPF.
- Build a mock microservice for API traffic generation.
- Capture and analyze API requests in real time.
- Build an API Discovery Pipeline for endpoint identification.
- Detect and analyze API security threats such as BOLA, BFLA, and Shadow APIs.
- Develop a scalable API security monitoring platform.

---

## Completed Features

- FastAPI-based mock REST API developed with Swagger UI support.
- HTTP request capture implemented using eBPF and Rust.
- Rust userspace application integrated with the Python analysis pipeline.
- HTTP request decoding, parsing, and validation completed.
- API Discovery Pipeline implemented for endpoint discovery and inventory generation.
- BOLA heuristic engine implemented for anomalous object access detection.
- Risk score calculation and runtime security alert generation implemented.
- Discovery reports and security logs generated automatically.
- API testing and validation completed using Swagger UI and Postman.

---

## Technology Stack

### Backend

- Python
- FastAPI
- Uvicorn

### Low-Level Development

- Rust
- eBPF
- libbpf-rs
- libbpf-cargo

### Development Tools

- Ubuntu
- Git
- GitHub
- Visual Studio Code
- Postman

---

## Project Structure

```text
API-Sentinel/
│
├── backend/       
├── docs/          
├── ebpf/         
├── tests/          
├── README.md
├── PROCEDURE.md
└── .gitignore
```
---

## Development Workflow

- Develop features on separate branches.
- Test changes before committing.
- Push updates to GitHub.
- Merge reviewed changes into the `main` branch.

---

## License

Developed as part of the **Axlero Internship Program** for educational and research purposes.

This repository is currently intended for learning and research. Licensing terms may be updated as the project evolves.
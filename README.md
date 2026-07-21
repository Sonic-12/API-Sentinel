# API-Sentinel

API-Sentinel is an enterprise-inspired API Security platform designed to monitor, analyze, and secure HTTP/REST API traffic using eBPF and Rust. The project provides real-time API traffic visibility by capturing HTTP requests at the kernel level and processing them through a Python-based analysis engine. It serves as a foundation for detecting API security threats such as Broken Object Level Authorization (BOLA), Broken Function Level Authorization (BFLA), and Shadow APIs.

> **Project Status:** Under Development

---

## Project Objectives

- Monitor HTTP/REST API traffic at the kernel level using eBPF.
- Build a mock microservice for API traffic generation.
- Capture and analyze API requests in real time.
- Build an API Discovery Pipeline for endpoint identification.
- Lay the foundation for API behavior analysis and threat detection such as BOLA, BFLA, and Shadow APIs.
- Develop a scalable API security monitoring platform.

---

## Current Development (Week 2)

- Building the API Discovery Pipeline
- Extracting API endpoint metadata
- Discovering unique API endpoints
- Building an API inventory
- Tracking endpoint usage statistics
- Preparing normalized API data for behavioural analysis
- Laying the foundation for Shadow API detection

## Completed (Week 1)

- Project repository initialized
- FastAPI backend developed
- Mock REST API endpoints implemented
- Swagger UI documentation enabled
- API testing completed using Swagger UI and Postman
- Rust userspace application integrated with the Python parser
- HTTP request decoding implemented
- HTTP request parsing implemented
- Basic request validation completed
- Security alert generation implemented
- Logging mechanism for suspicious requests
- Ubuntu development environment configured

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
## Project Structure

```text
API-Sentinel/
│
├── backend/        # FastAPI application and Python parser
├── docs/           # Project documentation
├── ebpf/           # Rust eBPF programs
├── tests/          # Testing results
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

## License

Copyright © 2026 API-Sentinel.

Developed as part of the **Axlero Internship Program** for educational and research purposes.

This repository is currently intended for learning and research. Licensing terms may be updated as the project evolves.
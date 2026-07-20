# API-Sentinel

API-Sentinel is an enterprise-inspired API Security platform designed to monitor, analyze, and secure HTTP/REST API traffic using eBPF and Rust. The project aims to provide real-time API traffic visibility, support behavioral analysis, and lay the foundation for detecting security threats such as Broken Object Level Authorization (BOLA) and Broken Function Level Authorization (BFLA) and Shadow APIs.

> **Project Status:** Under Development

---

## Project Objectives

- Monitor HTTP/REST API traffic at the kernel level using eBPF.
- Build a mock microservice for API traffic generation.
- Capture and analyze API requests in real time.
- Lay the foundation for API behavior analysis and threat detection like BOLA , BFLA and Shadow APIs
- Develop a scalable API security monitoring platform.

---

## Current Progress

### Completed
- Project repository initialized
- FastAPI mock microservice created
- REST API endpoints implemented
- Swagger UI documentation enabled
- API testing completed using Postman
- Ubuntu development environment configured
- GitHub repository configured

### In Progress
- Rust development environment setup
- eBPF project initialization

### Planned
- Kernel-level HTTP traffic interception
- Python traffic parser
- API behavior analysis
- Shadow API discovery
- BOLA detection
- Interactive dashboard

---

## Technology Stack

### Backend
- Python
- FastAPI
- Uvicorn

### Low-Level Development
- Rust
- eBPF
- Aya Framework

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
├── backend/          # FastAPI application
├── docs/             # Project documentation
├── ebpf/             # Rust eBPF programs (In Progress)
├── userspace/        # Rust userspace loader (Planned)
├── tests/            # Testing modules
├── README.md
└── .gitignore
```

---

## Getting Started

### Clone Repository

```bash
git clone https://github.com/Sonic-12/API-Sentinel.git
cd API-Sentinel
```

### Create Virtual Environment

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run the Backend

```bash
uvicorn app.main:app
```

### API Documentation

Open your browser:

```
http://127.0.0.1:8000/docs
```

---

## Development Workflow

- Feature development is performed on individual branches.
- Changes are reviewed before merging into the main branch.
- Every commit represents a meaningful project milestone.

---

## Future Roadmap

- Rust eBPF packet interception
- Python packet parser
- API traffic reconstruction
- Shadow API detection
- BOLA detection
- Security event dashboard
- Performance optimization

---

## License

This project is being developed as part of the **Axlero Internship Program** for educational and research purposes.
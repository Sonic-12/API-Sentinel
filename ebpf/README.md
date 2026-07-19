# API Sentinel (eBPF)

## Status

The eBPF module successfully captures outgoing HTTP response payloads from FastAPI/Uvicorn using a kprobe attached to `tcp_sendmsg_locked` and sends them to the Rust userspace through a Ring Buffer. Uses libbpf

### Completed

- eBPF program loading
- kprobe attachment
- Ring Buffer communication
- HTTP payload extraction
- Rust userspace integration
- Tested using FastAPI, curl and Postman

---

## How to Run

### 1. Start the eBPF loader

```bash
sudo ./target/debug/api-sentinel-libbpf
```

### 2. Start the backend

```bash
cd backend
source .venv/bin/activate
uvicorn app.main:app --reload
```

### 3. Generate traffic

Use Postman or:

```bash
curl http://127.0.0.1:8000/health
```

The Rust terminal should display the captured HTTP payload.

---

## Notes

- The current implementation captures **HTTP response payloads**.
- Payloads are limited to **256 bytes**.
- The project is still under active development.

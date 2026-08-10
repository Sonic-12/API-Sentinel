
## Prerequisites

- Ubuntu/Debian (uses `apt`, kprobes require a Linux kernel)
- Python 3.10+
- Node.js + npm
- `sudo` access (the eBPF pipeline needs root to attach kprobes)

---

## 1. Set Up the Python Backend

```bash
cd backend
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

---

## 2. Install Rust and Build Dependencies

```bash
sudo apt update

# Rust toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Build dependencies for the eBPF program
sudo apt install -y \
  clang \
  llvm \
  libelf-dev \
  libbpf-dev \
  pkg-config \
  build-essential \
  linux-headers-$(uname -r)
```

Verify the install:

```bash
cargo --version
rustc --version
clang --version
```

---

## Running the Stack

Four services run together, each in its own terminal, in this order.

### Terminal 1 — Target App (FastAPI)

```bash
cd API-Sentinel/backend
source .venv/bin/activate
uvicorn app.main:app
```

**Expected output:**
```text
INFO:     Uvicorn running on http://127.0.0.1:8000
```

---

### Terminal 2 — eBPF Capture + Parser + Discovery Pipeline

```bash
cd API-Sentinel/ebpf/api-sentinel-libbpf
cargo build
sudo ./target/debug/api-sentinel-libbpf | (
  cd ../../backend
  source .venv/bin/activate
  python -m parser.integration | python -m discovery.pipeline
)
```

**Expected output:**
```text
Control socket listening at /tmp/api-sentinel.sock
Listening for events...
```

---

### Terminal 3 — Dashboard API

```bash
cd API-Sentinel/backend
source .venv/bin/activate
uvicorn dashboard_api.main:app --port 8010 --reload
```

**Expected output:**
```text
INFO:     Uvicorn running on http://127.0.0.1:8010
```

---

### Terminal 4 — React Dashboard

```bash
cd API-Sentinel/frontend
npm run dev
```

**Expected output:**
```text
Local:   http://localhost:5173/
```

Open that URL in your browser 

---

## Generating Traffic

All four terminals need to stay open. To see anything on the dashboard, send traffic

- Generate your own traffic with `curl`, Postman, or the Swagger UI at `http://127.0.0.1:8000/docs`.
- OR Run the test suite: `python3 test.py` inside the `tests` folder — covers all attack scenarios automatically.

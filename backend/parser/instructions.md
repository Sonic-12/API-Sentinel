---
# Prerequisites

- Ubuntu Linux
- Python 3.10+
- Rust
- Cargo
- libbpf
- Clang/LLVM
- FastAPI
- Uvicorn
---
# Running API-Sentinel

## Step 1: Start the FastAPI Server

Open a terminal.

```bash
cd ~/Axlero/API-Sentinel/backend

source .venv/bin/activate

uvicorn app.main:app
```

Expected Output

```
INFO:     Uvicorn running on http://127.0.0.1:8000
```

Leave this terminal running.

---

## Step 2: Start eBPF + Python Pipeline

Open another terminal.

```bash
cd ~/Axlero/API-Sentinel/ebpf/api-sentinel-libbpf

sudo ./target/debug/api-sentinel-libbpf | \
(
cd ../../backend
source .venv/bin/activate
python -m parser.integration
)
```

Expected Output

```
Opening BPF skeleton...
BPF loaded successfully!
kprobes attached!
Listening for events...

decoder.py loaded
```

Leave this terminal running.

---

## Step 3: Send a Test Request


```

Open

```
http://127.0.0.1:8000/docs
```

in a browser.

---

# Expected Flow

```
HTTP Request
      │
      ▼
FastAPI
      │
      ▼
eBPF captures TCP packets
      │
      ▼
Rust receives packet
      │
      ▼
Rust converts packet → JSON
      │
      ▼
Python reads JSON
      │
      ▼
Hex Payload Decoder
      │
      ▼
HTTP Request Parser
      │
      ▼
Validators
      │
      ▼
Risk Score
```

---

# Current Features

- eBPF-based packet capture
- TCP request monitoring
- TCP response monitoring
- Rust userspace loader
- Ring Buffer communication
- JSON event generation
- Hex payload decoding
- HTTP request parsing
- Validation pipeline
- Risk scoring
- Safe error handling

---

# Current Status

## Week 1 ✅ Completed

Completed Components

- Project setup
- eBPF integration
- Rust loader
- JSON pipeline
- Python integration
- Request parser
- Validator
- Risk scoring
- End-to-end testing

---


# Stopping the Project

Press

```
CTRL + C
```

in each running terminal.

---

# rohith akula

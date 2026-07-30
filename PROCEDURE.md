# Procedure

## Clone Repository (VS Code)

```bash
git clone https://github.com/Sonic-12/API-Sentinel.git
cd API-Sentinel
```

---

## Create Virtual Environment

```bash
cd backend

python3 -m venv .venv

source .venv/bin/activate

pip install -r requirements.txt
```

---

## Install Rust and Build Dependencies (Ubuntu/Debian)

```bash
sudo apt update

# Install Rust Toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

source "$HOME/.cargo/env"

# Install Build Dependencies
sudo apt install -y \
clang \
llvm \
libelf-dev \
libbpf-dev \
pkg-config \
build-essential \
linux-headers-$(uname -r)
```

Verify the installation:

```bash
cargo --version
rustc --version
clang --version
```

---

# Step 1: Start the FastAPI Server

Open a terminal and navigate to the backend directory.

```bash
cd ~/Axlero/API-Sentinel/backend
source .venv/bin/activate
uvicorn app.main:app
```

Expected Output

```text
INFO:     Uvicorn running on http://127.0.0.1:8000
```

Leave this terminal running.

---

# Step 2: Start the eBPF + Python Pipeline

Open a new terminal.

```bash
cd ~/Axlero/API-Sentinel/ebpf/api-sentinel-libbpf && \
cargo clean && \
cargo build && \
sudo ./target/debug/api-sentinel-libbpf | \
(
  cd ../../backend
  source .venv/bin/activate
  python -m parser.integration | python -m discovery.pipeline
)

```

Expected Output

```text
Opening BPF skeleton...
BPF loaded successfully!
kprobes attached!
Listening for events...

decoder.py loaded
```

Leave this terminal running.

---

# Step 3: Simulate a BOLA Attack

Once both terminals are running successfully, generate authenticated API requests using either of the following methods.

### Option 1: Swagger UI

Open your browser and visit:

```text
http://127.0.0.1:8000/docs
```

Execute the following requests using the same Authorization token:

```text
Authorization: Bearer T1 (EXAMPLE)

GET /users/101
GET /users/102
GET /users/103
GET /users/104
GET /users/105
```

### Option 2: Postman

Open Postman and send the same requests to the FastAPI server.

Example:

```text
GET http://127.0.0.1:8000/users/101
GET http://127.0.0.1:8000/users/102
GET http://127.0.0.1:8000/users/103
GET http://127.0.0.1:8000/users/104
GET http://127.0.0.1:8000/users/105
```

Add the following request header:

```text
Authorization: Bearer T1 (EXAMPLE)
```

---

# Step 4: Verify Detection Output

After generating traffic, verify the following files:

```text
backend/discovery_report.json
```

and

```text
backend/alerts.log
```

These files contain the generated BOLA alerts, risk scores, and request details.

---
# Stopping the Application

To stop the FastAPI server and the eBPF pipeline, return to each running terminal and press:

```text
Ctrl + C
```

This will safely terminate both processes.

---

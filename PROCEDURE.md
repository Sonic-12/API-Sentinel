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


Listening for events...

decoder.py loaded
```

Leave this terminal running.

---

uvicorn dashboard_api.main:app --port 8010 --reload
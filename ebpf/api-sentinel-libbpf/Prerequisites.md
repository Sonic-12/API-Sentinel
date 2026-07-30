
# Prerequisites

Install the required packages before building.

## Ubuntu/Debian

```bash
sudo apt update

# Rust Toolchain
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source "$HOME/.cargo/env"

# Build dependencies
sudo apt install -y \
clang \
llvm \
libelf-dev \
libbpf-dev \
pkg-config \
build-essential \
linux-headers-$(uname -r)
```

Verify installation:

```bash
cargo --version
rustc --version
clang --version
```

---

# How to Run

## 1. Build the eBPF loader

```bash
cd ebpf/api-sentinel-libbpf
cargo clean (Optional)
cargo build
```

## 2. Start the eBPF loader

```bash
sudo ./target/debug/api-sentinel-libbpf
```

## 3. Start the backend

Open another terminal.

```bash
cd backend
source .venv/bin/activate
uvicorn app.main:app
```

## 4. Generate traffic

Use Postman, Browser or:

```bash
curl http://127.0.0.1:8000/health
```

The Rust terminal should display the captured raw ebpf data packet.

---

# Notes

- Captures HTTP response/request
- Uses **libbpf** and a **Ring Buffer** for kernel-to-userspace communication.
- Tested on **Ubuntu Linux**.
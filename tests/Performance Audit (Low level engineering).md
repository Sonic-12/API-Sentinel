# Mid-Project Performance Audit

## Objective

Evaluate the runtime overhead introduced by the API-Sentinel monitoring pipeline and verify that the latency remains below the required 5 ms threshold.

---

## Test Environment

- Operating System: Ubuntu
- Web Framework: FastAPI
- Server: Uvicorn
- Monitoring Stack:
  - eBPF (libbpf)
  - Python Parser
  - Discovery Pipeline
- Benchmark Tool: ApacheBench (ab)

Benchmark Configuration:

- Total Requests: 1000
- Concurrency Level: 10

---

## Performance Results

The monitoring pipeline was evaluated across representative API endpoints under identical benchmark conditions.

### GET /users/{id}

- Baseline latency: **11.428 ms**
- Latency with API-Sentinel: **15.576 ms**
- Monitoring overhead: **4.148 ms**
- Result: **PASS**

### GET /orders/{id}

- Baseline latency: **13.035 ms**
- Latency with API-Sentinel: **15.779 ms**
- Monitoring overhead: **2.744 ms**
- Result: **PASS**

### POST /login

- Baseline latency: **13.498 ms**
- Latency with API-Sentinel: **13.851 ms**
- Monitoring overhead: **0.353 ms**
- Result: **PASS**

### POST /register

- Baseline latency: **10.665 ms**
- Latency with API-Sentinel: **15.474 ms**
- Monitoring overhead: **4.809 ms**
- Result: **PASS**

---

## Average Monitoring Overhead

Average latency overhead:

**3.01 ms**

---

## Conclusion

The API-Sentinel monitoring pipeline was benchmarked under concurrent HTTP traffic using ApacheBench.

Across representative API endpoints, the monitoring stack introduced an average latency overhead of approximately **3.01 ms**, remaining below the required **5 ms** threshold while maintaining full runtime monitoring and API discovery functionality.
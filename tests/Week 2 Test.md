
## Test Environment

- Ubuntu Linux
- FastAPI
- eBPF with **libbpf** for kernel-level packet capture
- Rust user-space application
- Python HTTP parser
- BOLA Heuristic Engine
- JSON as the communication format

---

## Validation Performed

- Successfully extracted the Authorization header from captured HTTP requests.
- Verified mapping of authenticated users to requested object IDs.
- Confirmed baseline object assignment for authenticated users.
- Verified detection of anomalous access to multiple object IDs.
- Successfully generated BOLA alerts after the configured threshold.
- Verified progressive risk score escalation for suspicious activity.
- Confirmed successful integration of the BOLA detection engine with the request parsing pipeline.

---

## Sample Output


```json
{
    "method": "GET",
    "path": "/users/104",
    "query_parameters": {},
    "http_version": "HTTP/1.1",
    "headers": {
        "Host": "127.0.0.1:8000",
        "Authorization": "Bearer T1"
    },
    "body": "",
    "risk_score": 110,
    "alerts": [
        "Possible User ID Enumeration Detected",
        "Possible BOLA Attack: token baselined to object '101' also accessed 3 other object IDs ([102, 103, 104])"
    ]
}
```

```json
{
    "method": "GET",
    "path": "/users/105",
    "query_parameters": {},
    "http_version": "HTTP/1.1",
    "headers": {
        "Host": "127.0.0.1:8000",
        "Authorization": "Bearer T1"
    },
    "body": "",
    "risk_score": 125,
    "alerts": [
        "Possible User ID Enumeration Detected",
        "Possible BOLA Attack: token baselined to object '101' also accessed 4 other object IDs ([102, 103, 104, 105])"
    ]
}
```

---

## Result

All validation checks were completed successfully. The implemented BOLA heuristic engine reliably tracked authenticated users, learned baseline object access patterns, detected anomalous access to foreign object IDs, generated BOLA alerts, and progressively increased the risk score based on suspicious behavior.
## Test Environment

- Ubuntu Linux
- FastAPI
- eBPF with **libbpf** for kernel-level packet capture
- Rust user-space application
- Python Analytics Engine
- Traffic Control (TC) for kernel-level flow enforcement
- JSON as the communication format

---

## Validation Performed

- Successfully parsed HTTP requests captured through the eBPF pipeline.
- Verified extraction of Authorization headers and request metadata.
- Confirmed detection of User ID Enumeration and BOLA attacks.
- Verified Business Flow Rate Abuse detection using a sliding window algorithm.
- Confirmed progressive risk score calculation for suspicious activity.
- Verified successful integration of multiple analytics modules.
- Confirmed communication between the Python analytics engine and the Rust user-space application.
- Verified kernel-level flow enforcement through the eBPF Traffic Control (TC) program.
- Successfully validated the complete analytics and enforcement pipeline.

---

## Sample Output

### User ID Enumeration & BOLA Detection

```json
{
    "method": "GET",
    "path": "/users/203",
    "query_parameters": {},
    "http_version": "HTTP/1.1",
    "headers": {
        "Host": "127.0.0.1:8000",
        "Authorization": "Bearer Scenario2-Enumeration"
    },
    "body": "",
    "risk_score": 110,
    "alerts": [
        "Possible User ID Enumeration Detected for 'Bearer Scenario2-Enumeration'",
        "Possible BOLA Attack: token baselined to object '200' also accessed 3 other object IDs (['201', '202', '203'])"
    ]
}
```

### Business Flow Rate Abuse Detection

```json
{
    "method": "GET",
    "path": "/users/400",
    "query_parameters": {},
    "http_version": "HTTP/1.1",
    "headers": {
        "Host": "127.0.0.1:8000",
        "Authorization": "Bearer Scenario4-RateAbuse"
    },
    "body": "",
    "risk_score": 60,
    "alerts": [
        "Possible Bot / Rate Abuse: 10 requests to '/users/{id}' from 'Bearer Scenario4-RateAbuse' within 10s"
    ]
}
```

---

## Result

All validation checks were completed successfully. The implemented analytics engine successfully analyzed captured HTTP requests, detected User ID Enumeration, identified Broken Object Level Authorization (BOLA) attacks, detected Business Flow Rate Abuse using a sliding window algorithm, progressively increased the overall risk score based on suspicious behavior, and successfully triggered kernel-level flow enforcement through the Rust user-space application and eBPF Traffic Control (TC) program once the configured enforcement threshold was reached.
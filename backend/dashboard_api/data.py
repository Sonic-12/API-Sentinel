import json
import re
import time
from pathlib import Path

BACKEND_ROOT = Path(__file__).resolve().parent.parent
DISCOVERY_REPORT_PATH = BACKEND_ROOT / "discovery_report.json"
ALERTS_LOG_PATH = BACKEND_ROOT / "alerts.log"

BLOCK_THRESHOLD = 60  # matches parser/request_parser.py's block_flow trigger
TREND_WINDOW_SECONDS = 1800  # 30 minutes
TREND_BUCKETS = 10

_LOG_BLOCK_SEP = re.compile(r"\n-{10,}\n")

OWASP_CATALOG = [
    {"id": "API1", "title": "Broken Object Level Authorization", "category": "BOLA"},
    {"id": "API2", "title": "Broken Authentication", "category": "Missing Auth"},
    {"id": "API3", "title": "Broken Object Property Level Authorization", "category": None},
    {"id": "API4", "title": "Unrestricted Resource Consumption", "category": "Rate Abuse"},
    {"id": "API5", "title": "Broken Function Level Authorization", "category": "BFLA"},
    {"id": "API6", "title": "Unrestricted Access to Sensitive Business Flows", "category": None},
    {"id": "API7", "title": "Server Side Request Forgery", "category": None},
    {"id": "API8", "title": "Security Misconfiguration", "category": None},
    {"id": "API9", "title": "Improper Inventory Management", "category": "__shadow__"},
    {"id": "API10", "title": "Unsafe Consumption of APIs", "category": None},
]


def load_discovery_report() -> dict:
    if not DISCOVERY_REPORT_PATH.exists():
        return {}
    try:
        with open(DISCOVERY_REPORT_PATH, "r") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {}


def load_masked_logs(limit: int = 50) -> list:
    if not ALERTS_LOG_PATH.exists():
        return []
    try:
        raw = ALERTS_LOG_PATH.read_text()
    except OSError:
        return []

    entries = []
    for block in _LOG_BLOCK_SEP.split(raw):
        block = block.strip().strip("-").strip()
        if not block:
            continue
        try:
            entries.append(json.loads(block))
        except json.JSONDecodeError:
            continue

    return list(reversed(entries))[:limit]


def classify_alert(alert_text: str) -> str:
    text = (alert_text or "").lower()
    if "bola" in text:
        return "BOLA"
    if "enumeration" in text:
        return "Enumeration"
    if "rate abuse" in text or "bot" in text:
        return "Rate Abuse"
    if "sensitive path" in text:
        return "Sensitive Path"
    if "function level authorization" in text:
        return "BFLA"
    if "missing authorization" in text:
        return "Missing Auth"
    if "invalid http method" in text:
        return "Invalid Method"
    return "Other"


def _risk_bucket(score: int) -> str:
    if score <= 0:
        return "Clean"
    if score <= 40:
        return "Low"
    if score <= 80:
        return "Medium"
    return "High"


def compute_statistics(report: dict) -> dict:
    entries = report.get("access_log") or []
    total_requests = len(entries)

    attack_breakdown = {}
    risk_distribution = {"Clean": 0, "Low": 0, "Medium": 0, "High": 0}
    blocked_flows = 0
    alerts_generated = 0
    risk_sum = 0

    for entry in entries:
        score = entry.get("risk_score", 0) or 0
        risk_sum += score
        risk_distribution[_risk_bucket(score)] += 1
        if score >= BLOCK_THRESHOLD:
            blocked_flows += 1
        alerts = entry.get("alerts") or []
        if alerts:
            alerts_generated += 1
        for alert in alerts:
            category = classify_alert(alert)
            attack_breakdown[category] = attack_breakdown.get(category, 0) + 1

    average_risk = round(risk_sum / total_requests, 1) if total_requests else 0

    diff = report.get("diff") or {}
    shadow_endpoints = diff.get("shadow_endpoints") or []

    now = time.time()
    bucket_size = TREND_WINDOW_SECONDS / TREND_BUCKETS
    trend_counts = [0] * TREND_BUCKETS
    for entry in entries:
        ts = entry.get("timestamp")
        if ts is None:
            continue
        age = now - ts
        if age < 0 or age > TREND_WINDOW_SECONDS:
            continue
        idx = TREND_BUCKETS - 1 - min(TREND_BUCKETS - 1, int(age // bucket_size))
        trend_counts[idx] += 1
    trend = [
        {"label": f"-{int((TREND_BUCKETS - 1 - i) * bucket_size // 60)}m", "count": c}
        for i, c in enumerate(trend_counts)
    ]

    return {
        "total_requests": total_requests,
        "alerts_generated": alerts_generated,
        "blocked_flows": blocked_flows,
        "average_risk": average_risk,
        "observed_apis": len(report.get("observed_endpoints") or []),
        "shadow_apis": len(shadow_endpoints),
        "attack_breakdown": attack_breakdown,
        "risk_distribution": risk_distribution,
        "trend": trend,
    }


def compute_owasp_coverage(stats: dict) -> list:
    breakdown = stats.get("attack_breakdown", {})
    shadow_apis = stats.get("shadow_apis", 0)
    coverage = []
    for item in OWASP_CATALOG:
        if item["category"] == "__shadow__":
            observed = shadow_apis > 0
        elif item["category"] is None:
            observed = False
        else:
            observed = breakdown.get(item["category"], 0) > 0
        if observed:
            coverage.append({"id": item["id"], "title": item["title"]})
    return coverage
import asyncio
import json

from fastapi import FastAPI, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse

from dashboard_api.data import (
    load_discovery_report,
    load_masked_logs,
    compute_statistics,
    compute_owasp_coverage,
)

app = FastAPI(title="API-Sentinel Dashboard API")

# Dev-only: the React app runs on a different origin (Vite's dev server).
# Tighten this to the deployed frontend origin before shipping anywhere real.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET"],
    allow_headers=["*"],
)


@app.get("/api/health")
def health():
    return {"status": "healthy", "service": "api-sentinel-dashboard"}


@app.get("/api/discovery")
def discovery():
    report = load_discovery_report()
    diff = report.get("diff") or {}
    return {
        "observed_endpoints": report.get("observed_endpoints") or [],
        "shadow_endpoints": diff.get("shadow_endpoints") or [],
        "unseen_documented_endpoints": diff.get("unseen_documented_endpoints") or [],
        "matched_count": diff.get("matched_count", 0),
    }


@app.get("/api/alerts")
def alerts(limit: int = Query(100, ge=1, le=500), only_flagged: bool = True):
    report = load_discovery_report()
    entries = report.get("access_log") or []
    if only_flagged:
        entries = [e for e in entries if e.get("alerts")]
    return list(reversed(entries))[:limit]


@app.get("/api/statistics")
def statistics():
    report = load_discovery_report()
    return compute_statistics(report)


@app.get("/api/owasp")
def owasp():
    report = load_discovery_report()
    stats = compute_statistics(report)
    return compute_owasp_coverage(stats)


@app.get("/api/logs")
def logs(limit: int = Query(50, ge=1, le=200)):
    return load_masked_logs(limit)


@app.get("/api/alerts/stream")
async def alerts_stream():
    """
    Server-Sent Events feed of newly flagged requests.

    Polls discovery_report.json on the server side (same source of truth as
    every other endpoint) and pushes only the entries the client hasn't seen
    yet, keyed by count of flagged entries. This replaces client-side
    polling for the Alerts page with a real push channel, while every other
    page keeps using the plain REST + polling model -- no reason to add
    connection-management complexity where a 3s poll is already honest.
    """

    async def event_generator():
        last_count = 0
        while True:
            report = load_discovery_report()
            entries = report.get("access_log") or []
            flagged = [e for e in entries if e.get("alerts")]

            # Report file was regenerated/truncated (e.g. harness re-run) --
            # reset our watermark instead of trying to diff against a
            # smaller list.
            if len(flagged) < last_count:
                last_count = 0

            if len(flagged) > last_count:
                for entry in flagged[last_count:]:
                    yield f"data: {json.dumps(entry)}\n\n"
                last_count = len(flagged)
            else:
                # Heartbeat comment keeps intermediary proxies (e.g. Vite's
                # dev proxy) from timing out an idle connection.
                yield ": heartbeat\n\n"

            await asyncio.sleep(2)

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "X-Accel-Buffering": "no",
        },
    )
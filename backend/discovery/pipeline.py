# Discovery pipeline entrypoint. Reads parser.integration's stdout, feeds it into DiscoveryEngine, and writes discovery_report.json.


from __future__ import annotations

import json
import sys
import urllib.request
from typing import Optional

from .inventory import DiscoveryEngine
from .report_writer import ReportWriter

OFFICIAL_SPEC_URL = "http://127.0.0.1:8000/openapi.json"
DISCOVERY_REPORT_PATH = "discovery_report.json"

_REQUIRED_KEYS = frozenset({"method", "path", "headers"})


def iter_json_objects(stream):
    # Non-JSON text between objects (log lines, error messages) is
    # silently skipped rather than treated as an error.
    decoder = json.JSONDecoder()
    buffer = ""

    for chunk in stream:
        buffer += chunk
        while True:
            buffer = buffer.lstrip()
            if not buffer:
                break

            start = buffer.find("{")
            if start == -1:
                buffer = ""
                break
            if start > 0:
                buffer = buffer[start:]

            try:
                obj, idx = decoder.raw_decode(buffer)
            except json.JSONDecodeError:
                break

            buffer = buffer[idx:]
            yield obj


def fetch_official_spec(url: str, timeout: float = 2.0) -> Optional[dict]:
    try:
        with urllib.request.urlopen(url, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"[Discovery] Could not fetch official spec from {url}: {e}", file=sys.stderr)
        return None


def main():
    engine = DiscoveryEngine()
    official_spec = fetch_official_spec(OFFICIAL_SPEC_URL)
    writer = ReportWriter(DISCOVERY_REPORT_PATH)

    try:
        for obj in iter_json_objects(sys.stdin):
            if not isinstance(obj, dict):
                continue
            if not _REQUIRED_KEYS.issubset(obj.keys()):
                continue

            engine.observe_dict(obj)
            writer.write(engine, official_spec)
    finally:
        writer.write(engine, official_spec, force=True)


if __name__ == "__main__":
    main()
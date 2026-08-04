from __future__ import annotations

import json
import os
import tempfile
import time
from typing import Optional

from .inventory import DiscoveryEngine
from .openapi_generator import build_openapi
from .comparator import diff_against_official

REPORT_MIN_INTERVAL_SECONDS = 0.5


class ReportWriter:
    def __init__(self, path: str = "discovery_report.json", min_interval: float = REPORT_MIN_INTERVAL_SECONDS):
        self.path = path
        self.min_interval = min_interval
        self._last_write = 0.0
        self._target_dir = os.path.dirname(os.path.abspath(path)) or "."

    def write(self, engine: DiscoveryEngine, official_spec: Optional[dict], force: bool = False) -> None:
        now = time.monotonic()
        if not force and (now - self._last_write) < self.min_interval:
            return
        self._last_write = now
        self._write_now(engine, official_spec)

    def _write_now(self, engine: DiscoveryEngine, official_spec: Optional[dict]) -> None:
        # Write to a temp file then os.replace() into place, so a
        # concurrent reader never sees a half-written file.
        report = {"discovered_openapi": build_openapi(engine)}
        report["diff"] = diff_against_official(engine, official_spec) if official_spec is not None else None
        report["observed_endpoints"] = [record.to_dict() for record in engine.inventory()]
        report["access_log"] = engine.access_log.to_list()

        fd, tmp_path = tempfile.mkstemp(dir=self._target_dir, prefix=".discovery_report_", suffix=".tmp")
        try:
            with os.fdopen(fd, "w") as f:
                json.dump(report, f, indent=2)
            os.replace(tmp_path, self.path)
        except BaseException:
            try:
                os.remove(tmp_path)
            except OSError:
                pass
            raise
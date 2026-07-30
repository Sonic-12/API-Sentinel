
from __future__ import annotations

import time
from collections import deque
from dataclasses import dataclass, field
from typing import Optional

from .normalizer import normalize_path, extract_object_id

MAX_ACCESS_LOG_SIZE = 500


@dataclass
class AccessEvent:
    identity: Optional[str]
    method: str
    path_template: str
    object_id: Optional[str]
    timestamp: float
    risk_score: int = 0
    alerts: list = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "identity": self.identity,
            "method": self.method,
            "path_template": self.path_template,
            "object_id": self.object_id,
            "timestamp": self.timestamp,
            "risk_score": self.risk_score,
            "alerts": self.alerts,
        }


class AccessLog:
    def __init__(self, maxlen: int = MAX_ACCESS_LOG_SIZE):
        self.events: deque[AccessEvent] = deque(maxlen=maxlen)

    def record(self, request: dict) -> None:
        method = request.get("method", "")
        path = request.get("path", "")
        if not method or not path:
            return

        headers = request.get("headers") or {}

        event = AccessEvent(
            identity=headers.get("Authorization"),
            method=method,
            path_template=normalize_path(path),
            object_id=extract_object_id(path),
            timestamp=time.time(),
            risk_score=request.get("risk_score", 0),
            alerts=list(request.get("alerts", []) or []),
        )
        self.events.append(event)

    def to_list(self) -> list[dict]:
        return [e.to_dict() for e in self.events]
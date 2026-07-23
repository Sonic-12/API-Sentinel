"""EndpointRecord and DiscoveryEngine -- the live registry of observed endpoints."""

from __future__ import annotations

import time
from dataclasses import dataclass, field, asdict
from typing import Optional

from .normalizer import normalize_path, infer_schema
from .access_log import AccessLog


@dataclass
class EndpointRecord:
    method: str
    path_template: str
    first_seen: float = field(default_factory=time.time)
    last_seen: float = field(default_factory=time.time)
    hit_count: int = 0
    example_paths: set = field(default_factory=set)
    query_param_names: set = field(default_factory=set)
    body_schema: Optional[dict] = None

    def observe(self, path: str, query_parameters: dict, body) -> None:
        self.last_seen = time.time()
        self.hit_count += 1
        if len(self.example_paths) < 5:
            self.example_paths.add(path)
        if isinstance(query_parameters, dict):
            self.query_param_names.update(query_parameters.keys())
        if isinstance(body, dict) and body:
            new_schema = infer_schema(body)
            if self.body_schema is None:
                self.body_schema = new_schema
            else:
                self.body_schema.setdefault("properties", {}).update(new_schema.get("properties", {}))

    def to_dict(self) -> dict:
        d = asdict(self)
        d["example_paths"] = sorted(self.example_paths)
        d["query_param_names"] = sorted(self.query_param_names)
        return d


class DiscoveryEngine:
    def __init__(self):
        self.registry: dict[tuple[str, str], EndpointRecord] = {}
        self.access_log = AccessLog()

    def observe_dict(self, record: dict) -> None:
        method = record.get("method", "")
        path = record.get("path", "")
        if not method or not path:
            return

        template = normalize_path(path)
        key = (method, template)

        entry = self.registry.get(key)
        if entry is None:
            entry = EndpointRecord(method=method, path_template=template)
            self.registry[key] = entry

        entry.observe(path, record.get("query_parameters", {}) or {}, record.get("body"))
        self.access_log.record(record)

    def inventory(self) -> list[EndpointRecord]:
        return list(self.registry.values())
# Builds an OpenAPI 3.0 document from a DiscoveryEngine's observed traffic.

from __future__ import annotations

from .inventory import DiscoveryEngine


def build_openapi(
    engine: DiscoveryEngine,
    title: str = "API-Sentinel Discovered Spec",
    version: str = "0.1.0",
) -> dict:
    paths: dict = {}
    for record in engine.registry.values():
        entry = paths.setdefault(record.path_template, {})
        op = {
            "summary": f"Discovered from live traffic ({record.hit_count} request(s) observed)",
            "parameters": [
                {"name": name, "in": "query", "schema": {"type": "string"}}
                for name in sorted(record.query_param_names)
            ],
            "responses": {"200": {"description": "Observed response"}},
        }
        if record.body_schema:
            op["requestBody"] = {"content": {"application/json": {"schema": record.body_schema}}}
        entry[record.method.lower()] = op

    return {"openapi": "3.0.0", "info": {"title": title, "version": version}, "paths": paths}
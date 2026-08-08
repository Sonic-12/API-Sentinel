from __future__ import annotations

from .inventory import DiscoveryEngine
from .normalizer import HTTP_METHODS, path_shape

_IGNORED_SHADOW_PATHS = frozenset({"/docs", "/openapi.json", "/redoc"})


def diff_against_official(engine: DiscoveryEngine, official_spec: dict) -> dict:
    official_keys: dict[tuple[str, str], str] = {}
    for raw_path, methods in official_spec.get("paths", {}).items():
        shape = path_shape(raw_path)
        for method in methods:
            if method.lower() in HTTP_METHODS:
                official_keys[(method.upper(), shape)] = raw_path

    observed_keys: dict[tuple[str, str], str] = {}
    for (method, template) in engine.registry.keys():
        observed_keys[(method, path_shape(template))] = template

    shadow_endpoints = [
        {"method": m, "path": t}
        for (m, shape), t in observed_keys.items()
        if (m, shape) not in official_keys and t not in _IGNORED_SHADOW_PATHS
    ]
    unseen_documented_endpoints = [
        {"method": m, "path": p} for (m, shape), p in official_keys.items() if (m, shape) not in observed_keys
    ]

    return {
        "shadow_endpoints": shadow_endpoints,
        "unseen_documented_endpoints": unseen_documented_endpoints,
        "matched_count": len(set(observed_keys) & set(official_keys)),
    }
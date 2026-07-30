"""Path normalization and JSON schema inference."""

from __future__ import annotations

import re
from typing import Optional

_ID_SEGMENT = re.compile(
    r"^("
    r"\d+"
    r"|[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
    r")$"
)

HTTP_METHODS = frozenset({"get", "post", "put", "delete", "patch", "head", "options"})


def normalize_path(path: str) -> str:
    segments = path.strip("/").split("/")
    normalized = ["{id}" if _ID_SEGMENT.match(seg) else seg for seg in segments]
    return "/" + "/".join(normalized)


def extract_object_id(path: str) -> Optional[str]:
    """Returns the last concrete ID segment in the path (numeric or
    UUID), or None if the path has no ID segment. This is the object
    identifier a BOLA check correlates against a caller's identity."""
    segments = path.strip("/").split("/")
    for seg in reversed(segments):
        if _ID_SEGMENT.match(seg):
            return seg
    return None


def path_shape(path: str) -> str:
    segments = path.strip("/").split("/")
    shaped = ["{}" if seg.startswith("{") and seg.endswith("}") else seg for seg in segments]
    return "/" + "/".join(shaped)


def infer_schema(value):
    if value is None:
        return {"type": "string", "nullable": True}
    if isinstance(value, bool):
        return {"type": "boolean"}
    if isinstance(value, int):
        return {"type": "integer"}
    if isinstance(value, float):
        return {"type": "number"}
    if isinstance(value, dict):
        return {"type": "object", "properties": {k: infer_schema(v) for k, v in value.items()}}
    if isinstance(value, list):
        if value:
            return {"type": "array", "items": infer_schema(value[0])}
        return {"type": "array", "items": {}}
    return {"type": "string"}
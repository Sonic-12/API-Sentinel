"""discovery -- Week 2 pipeline stage. Run as: python -m discovery.pipeline"""

from .inventory import EndpointRecord, DiscoveryEngine
from .normalizer import normalize_path, path_shape, infer_schema, extract_object_id
from .openapi_generator import build_openapi
from .comparator import diff_against_official
from .report_writer import ReportWriter
from .access_log import AccessLog, AccessEvent

__all__ = [
    "EndpointRecord",
    "DiscoveryEngine",
    "normalize_path",
    "path_shape",
    "infer_schema",
    "extract_object_id",
    "build_openapi",
    "diff_against_official",
    "ReportWriter",
    "AccessLog",
    "AccessEvent",
]
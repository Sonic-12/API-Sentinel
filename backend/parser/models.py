from dataclasses import dataclass, field


@dataclass
class ParsedRequest:

    method: str
    path: str
    query_parameters: dict
    http_version: str
    headers: dict
    body: dict | str

    risk_score: int = 0

    alerts: list = field(default_factory=list)
    
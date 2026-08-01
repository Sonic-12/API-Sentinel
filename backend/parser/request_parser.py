import json
from dataclasses import asdict
from parser.models import ParsedRequest
from parser.loger import log_request
from parser.enforcer import block_flow
from parser.validators import (
    check_http_method,
    check_authorization,
    check_sensitive_path,
    check_enumeration
)
from parser.bola_engine import BolaEngine

previous_object_id = []
bola_engine = BolaEngine()


def parse_request(raw_request, conn_id=None, saddr=None, daddr=None, sport=None, dport=None):
    lines = raw_request.strip().splitlines()
    body = ""
    requested_line = lines[0]
    parts = requested_line.split()

    if len(parts) != 3:
        print("Malformed HTTP Request")
        return

    method = parts[0]
    valid_methods = ["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"]

    path = parts[1]
    query_parameters = {}
    if "?" in path:
        path, query_string = path.split("?", 1)
        for parameter in query_string.split("&"):
            key, value = parameter.split("=", 1)
            query_parameters[key] = value
    http_version = parts[2]

    headers = {}
    for line in lines[1:]:
        if ": " in line:
            key, value = line.split(": ", 1)
            headers[key] = value

    if "" in lines:
        body_start = lines.index("") + 1
        body = "\n".join(lines[body_start:])
        try:
            body = json.loads(body)
        except json.JSONDecodeError:
            pass

    authorization = headers.get("Authorization")

    parsed_request = ParsedRequest(
        method=method,
        path=path,
        query_parameters=query_parameters,
        http_version=http_version,
        headers=headers,
        body=body
    )

    check_http_method(method, parsed_request, valid_methods)
    check_authorization(headers, path, parsed_request)
    check_sensitive_path(path, parsed_request)

    object_id = check_enumeration(path, previous_object_id, parsed_request)
    bola_engine.evaluate(authorization, object_id, parsed_request)

    print(json.dumps(asdict(parsed_request), indent=4))

    if parsed_request.risk_score > 0:
        log_request(parsed_request)

    if parsed_request.risk_score >= 60:  # BOLA_RISK_BASE threshold -> enforce
        block_flow(saddr, daddr, sport, dport)
import json
from parser.models import ParsedRequest, ip_to_str
from parser.loger import log_request
from parser.enforcer import block_flow
from parser.masking import to_masked_dict
from parser.validators import (
    check_http_method,
    check_authorization,
    check_sensitive_path,
    check_enumeration,
    check_function_level_authorization
)
from parser.bola_engine import BolaEngine
from parser.rate_limiter import RateLimiter

previous_object_ids = {}
function_access_history = {}
bola_engine = BolaEngine()
rate_limiter = RateLimiter()


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
        if line == "":
            break
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
    client_id = headers.get("X-Client-Id")

    parsed_request = ParsedRequest(
        method=method,
        path=path,
        query_parameters=query_parameters,
        http_version=http_version,
        headers=headers,
        body=body,
        conn_id=conn_id,
        client_ip=ip_to_str(saddr),
        server_ip=ip_to_str(daddr),
        client_id=client_id,
        sport=sport,
        dport=dport
    )

    check_http_method(method, parsed_request, valid_methods)
    check_authorization(headers, path, parsed_request)
    check_sensitive_path(path, parsed_request)

    identity = authorization or client_id or parsed_request.client_ip or "unknown"

    object_id = check_enumeration(path, identity, previous_object_ids, parsed_request)
    check_function_level_authorization(path, identity, function_access_history, parsed_request)
    bola_engine.evaluate(identity, object_id, parsed_request)
    rate_limiter.evaluate(identity, path, parsed_request)

    print(json.dumps(to_masked_dict(parsed_request), indent=4))

    if parsed_request.risk_score > 0:
        log_request(parsed_request)

    if parsed_request.risk_score >= 60:
        block_flow(saddr, daddr, sport, dport)
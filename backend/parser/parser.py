import json
from dataclasses import asdict
from os import path
from wsgiref import headers
from sample_data import RAW_HTTP_REQUESTS
from models import ParsedRequest
from loger import log_request
from validators import (
    check_http_method,
    check_authorization,
    check_sensitive_path,
    check_enumeration,
    check_bola
)
previous_object_id = []
token_access_history = {}
def parse_request(raw_request):
    lines = raw_request.strip().splitlines()
    body = ""
    requested_line = lines[0]
    parts=requested_line.split()

    if len(parts) != 3:
        print("Malformed HTTP Request")
        return

    method = parts[0]
    valid_methods = [
    "GET",
    "POST",
    "PUT",
    "DELETE",
    "PATCH",
    "HEAD",
    "OPTIONS"
   ]
    path = parts[1]
    query_parameters = {}
    if "?" in path:
        path, query_string = path.split("?", 1)
        for parameter in query_string.split("&"):
            key, value = parameter.split("=", 1)
            query_parameters[key] = value
    http_version = parts[2]
#print(f"Method: {method}\nPath: {path}\nHTTP Version: {http_version}")
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
#print("\nHeaders:")
#for key, value in headers.items():
#    print(f"{key}: {value}")

    parsed_request = ParsedRequest(
    method=method,
    path=path,
    query_parameters=query_parameters,
    http_version=http_version,
    headers=headers,
    body=body
)
    
    check_http_method(method, parsed_request, valid_methods)
    check_authorization(headers, parsed_request)
    check_sensitive_path(path, parsed_request)

    object_id = check_enumeration(
    path,
    previous_object_id,
    parsed_request
    )
    check_bola(
    authorization,
    object_id,
    token_access_history,
    parsed_request
    )
 
    #print("History of Object IDs:", previous_object_id)
    #print("Token Access History:", token_access_history)
    #print("Query Parameters:", query_parameters)
    #print(body)
    print(json.dumps(asdict(parsed_request), indent=4))
    if parsed_request.risk_score > 0:
        log_request(parsed_request)
for request in RAW_HTTP_REQUESTS:
    parse_request(request)
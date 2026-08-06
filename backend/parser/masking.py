from dataclasses import asdict
import copy
import hashlib
import re

SENSITIVE_HEADERS = {"authorization", "cookie", "set-cookie", "x-api-key", "x-client-id"}

REDACT_FULLY = {"password", "passwd", "pwd", "secret", "token", "ssn",
                 "credit_card", "card_number", "cvv", "api_key"}
PARTIAL_MASK = {"username", "user", "email", "phone", "full_name", "name"}

_EMAIL_RE = re.compile(r"^([^@]{1,3})[^@]*(@.+)$")


def _hash_token(value: str) -> str:
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return digest


_ALREADY_MASKED = re.compile(r"^masked:[0-9a-f]{12}$")


def mask_authorization(value):
    if not value:
        return value
    scheme, sep, token = value.partition(" ")
    if not sep:
        if _ALREADY_MASKED.match(value):
            return value 
        return f"masked:{_hash_token(value)}"
    if _ALREADY_MASKED.match(token):
        return value  
    return f"{scheme} masked:{_hash_token(token)}"


def mask_ip(value):
    if not value:
        return value
    if str(value).startswith("masked:"):
        return value
    return f"masked:{_hash_token(str(value))}"


def _mask_partial_string(value: str) -> str:
    if not isinstance(value, str) or not value:
        return value
    m = _EMAIL_RE.match(value)
    if m:
        return f"{m.group(1)}***{m.group(2)}"
    if len(value) <= 2:
        return "*" * len(value)
    return value[:2] + "*" * (len(value) - 2)


def mask_headers(headers: dict) -> dict:
    if not headers:
        return headers
    masked = {}
    for key, value in headers.items():
        lower = key.lower()
        if lower == "authorization":
            masked[key] = mask_authorization(value)
        elif lower in SENSITIVE_HEADERS:
            masked[key] = f"masked:{_hash_token(str(value))}"
        else:
            masked[key] = value
    return masked


def mask_body(body):
    if isinstance(body, dict):
        masked = {}
        for key, value in body.items():
            lower = key.lower()
            if isinstance(value, dict):
                masked[key] = mask_body(value)
            elif isinstance(value, list):
                masked[key] = [mask_body(v) if isinstance(v, dict) else v for v in value]
            elif lower in REDACT_FULLY:
                masked[key] = "***"
            elif lower in PARTIAL_MASK:
                masked[key] = _mask_partial_string(str(value))
            else:
                masked[key] = value
        return masked
    return body


def mask_alert_text(alert: str, raw_authorization=None, client_ip=None) -> str:
    if not isinstance(alert, str):
        return alert
    text = alert
    if raw_authorization and raw_authorization in text:
        text = text.replace(raw_authorization, mask_authorization(raw_authorization))
    if client_ip:
        anon_raw = f"anon:{client_ip}"
        if anon_raw in text:
            text = text.replace(anon_raw, f"anon:masked:{_hash_token(client_ip)}")
    return text


def mask_alerts(alerts, raw_authorization=None, client_ip=None) -> list:
    return [mask_alert_text(a, raw_authorization, client_ip) for a in (alerts or [])]


def to_masked_dict(parsed_request) -> dict:

    data = asdict(parsed_request)
    raw_authorization = (parsed_request.headers or {}).get("Authorization")
    client_ip = getattr(parsed_request, "client_ip", None)

    data["headers"] = mask_headers(copy.deepcopy(data.get("headers")))
    data["body"] = mask_body(copy.deepcopy(data.get("body")))
    data["query_parameters"] = mask_body(copy.deepcopy(data.get("query_parameters")))
    data["alerts"] = mask_alerts(data.get("alerts"), raw_authorization, client_ip)
    data["client_ip"] = mask_ip(client_ip)
    return data
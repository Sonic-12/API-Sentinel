import re

INVALID_METHOD_RISK = 20
SENSITIVE_PATH_RISK = 30
MISSING_AUTH_RISK = 40
ENUMERATION_RISK = 50
BOLA_RISK = 60
BFLA_RISK = 70

ENUMERATION_WINDOW = 20
ENUMERATION_TTL_SECONDS = 900
ENUMERATION_MAX_IDENTITIES = 5000

FUNCTION_SENSITIVE_PATHS = ("/admin", "/config", "/internal", "/debug", "/manage")

_UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
_ID_SEGMENT = re.compile(rf"^\d+$|^{_UUID}$")


def check_http_method(method, parsed_request, valid_methods):

    if method not in valid_methods:
        parsed_request.risk_score += INVALID_METHOD_RISK
        parsed_request.alerts.append(
            f"Invalid HTTP Method: {method}"
        )


def check_authorization(headers, path, parsed_request):

    protected_paths = [
        "/admin",
        "/manage",
        "/users",
        "/orders",
        "/profile"
    ]

    for protected_path in protected_paths:
        if path.startswith(protected_path):

            if "Authorization" not in headers:
                parsed_request.risk_score += MISSING_AUTH_RISK
                parsed_request.alerts.append(
                    "Missing Authorization Header"
                )

            break


def check_sensitive_path(path, parsed_request):

    sensitive_paths = [
        "/admin",
        "/config",
        "/internal",
        "/debug",
        "/manage"
    ]

    if any(path.startswith(p) for p in sensitive_paths):
        parsed_request.risk_score += SENSITIVE_PATH_RISK
        parsed_request.alerts.append(
            "Accessing sensitive path"
        )


def _extract_object_id(path):
    segment = path.rstrip("/").split("/")[-1]
    if _ID_SEGMENT.match(segment):
        return segment
    return None


def check_enumeration(path, identity, history, parsed_request, lock=None):
    import time
    from contextlib import nullcontext
    now = time.time()

    with (lock or nullcontext()):
        stale = [k for k, rec in history.items() if now - rec["last_seen"] > ENUMERATION_TTL_SECONDS]
        for k in stale:
            del history[k]

        object_id = _extract_object_id(path)

        if identity not in history:
            if len(history) >= ENUMERATION_MAX_IDENTITIES:
                oldest = min(history, key=lambda k: history[k]["last_seen"])
                del history[oldest]
            history[identity] = {"ids": [], "last_seen": now}

        rec = history[identity]
        rec["last_seen"] = now

        if object_id is not None:
            rec["ids"].append(object_id)
            if len(rec["ids"]) > ENUMERATION_WINDOW:
                rec["ids"] = rec["ids"][-ENUMERATION_WINDOW:]

        ids = list(rec["ids"])

    if len(ids) >= 3:
        last_three = ids[-3:]
        if all(x.isdigit() for x in last_three):
            nums = [int(x) for x in last_three]
            if nums[1] == nums[0] + 1 and nums[2] == nums[1] + 1:
                parsed_request.risk_score += ENUMERATION_RISK
                parsed_request.alerts.append(
                    f"Possible User ID Enumeration Detected for '{identity}'"
                )

    return object_id


def check_function_level_authorization(path, identity, history, parsed_request, lock=None):
    import time
    from contextlib import nullcontext
    now = time.time()

    with (lock or nullcontext()):
        stale = [k for k, rec in history.items() if now - rec["last_seen"] > ENUMERATION_TTL_SECONDS]
        for k in stale:
            del history[k]

        is_sensitive = any(path.startswith(p) for p in FUNCTION_SENSITIVE_PATHS)

        if identity not in history:
            if len(history) >= ENUMERATION_MAX_IDENTITIES:
                oldest = min(history, key=lambda k: history[k]["last_seen"])
                del history[oldest]
            history[identity] = {"seen_normal": False, "seen_sensitive": False, "last_seen": now}

        rec = history[identity]
        rec["last_seen"] = now
        was_seen_normal = rec["seen_normal"]

        if is_sensitive:
            rec["seen_sensitive"] = True
        else:
            rec["seen_normal"] = True

    if is_sensitive:
        if was_seen_normal:
            parsed_request.risk_score += BFLA_RISK
            parsed_request.alerts.append(
                f"Possible Broken Function Level Authorization: '{identity}' previously only "
                f"accessed standard endpoints, now accessing privileged path '{path}'"
            )
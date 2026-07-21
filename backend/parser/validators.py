INVALID_METHOD_RISK = 20
SENSITIVE_PATH_RISK = 30
MISSING_AUTH_RISK = 40
ENUMERATION_RISK = 50
BOLA_RISK = 60

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

def check_enumeration(path, previous_object_id, parsed_request):

    object_id = None

    if path.startswith("/users/"):
        user_id = path.split("/")[-1]

        if user_id.isdigit():
            object_id = int(user_id)

    if object_id is not None:
        previous_object_id.append(object_id)

    if len(previous_object_id) >= 3:

        last_three = previous_object_id[-3:]

        if (
            last_three[1] == last_three[0] + 1 and
            last_three[2] == last_three[1] + 1
        ):
            parsed_request.risk_score += ENUMERATION_RISK
            parsed_request.alerts.append(
                "Possible User ID Enumeration Detected"
            )

    return object_id
def check_bola(
    authorization,
    object_id,
    token_access_history,
    parsed_request
):

    if object_id is None:
        return

    if not authorization:
        return

    if authorization not in token_access_history:
        token_access_history[authorization] = []

    token_access_history[authorization].append(object_id)

    accessed_ids = token_access_history[authorization]
    unique_ids = set(accessed_ids)

    if len(unique_ids) >= 3:
        parsed_request.risk_score += BOLA_RISK
        parsed_request.alerts.append(
            "Possible BOLA Attack: Same token accessing multiple object IDs"
        )
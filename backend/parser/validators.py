def check_http_method(method, parsed_request, valid_methods):

    if method not in valid_methods:
        parsed_request.risk_score += 20
        parsed_request.alerts.append(
            f"Invalid HTTP Method: {method}"
        )

def check_authorization(headers, parsed_request):

    if "Authorization" not in headers:
        parsed_request.risk_score += 40
        parsed_request.alerts.append(
            "Missing Authorization Header"
        )

def check_sensitive_path(path, parsed_request):

    sensitive_paths = [
        "/admin",
        "/config",
        "/internal",
        "/debug",
        "/manage"
    ]

    for sensitive_path in sensitive_paths:
        if path.startswith(sensitive_path):
            parsed_request.alerts.append(
                f"Accessing sensitive path: {sensitive_path}"
            )
            parsed_request.risk_score += 30
            break

def check_enumeration(path, previous_object_id, parsed_request):

    object_id = None

    if path.startswith("/users/"):
        try:
            object_id = int(path.split("/")[-1])
        except ValueError:
            object_id = None

    print(f"Object ID: {object_id}")

    if object_id is not None:
        previous_object_id.append(object_id)

    if len(previous_object_id) >= 3:

        last_three = previous_object_id[-3:]

        if (
            last_three[1] == last_three[0] + 1 and
            last_three[2] == last_three[1] + 1
        ):
            parsed_request.risk_score += 50
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

    if authorization and object_id is not None:

        if authorization not in token_access_history:
            token_access_history[authorization] = []

        token_access_history[authorization].append(object_id)

        accessed_ids = token_access_history[authorization]
        unique_ids = set(accessed_ids)

        if len(unique_ids) >= 3:
            parsed_request.risk_score += 60
            parsed_request.alerts.append(
                "Possible BOLA Attack: Same token accessing multiple object IDs"
            )
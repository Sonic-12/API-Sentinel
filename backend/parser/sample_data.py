RAW_HTTP_REQUESTS = [
"""
HELLO /users/100?role=admin&status=active HTTP/1.1
Host: localhost:8000
Authorization: Bearer Token123
User-Agent: PostmanRuntime/7.45.0
Accept: */*
""",
"""
GET /users/101?role=admin&status=active HTTP/1.1
Host: localhost:8000
Authorization: Bearer Token123
User-Agent: PostmanRuntime/7.45.0
Accept: */*
""",
"""
GET /users/110?role=tester&status=active HTTP/1.1
Host: localhost:8000
Authorization: Bearer Token143
User-Agent: PostmanRuntime/7.50.0
Accept: */*
""",
"""
GET /users/108?role=admin&status=active HTTP/1.1
Host: localhost:8000
Authorization: Bearer Token123
User-Agent: PostmanRuntime/7.45.0
Accept: */*
""",
"""
GET /users/104?role=admin&status=active HTTP/1.1
Host: localhost:8000
Authorization: Bearer Token123
User-Agent: PostmanRuntime/7.45.0
Accept: */*
""",

"""POST /login HTTP/1.1
Host: localhost:8000
Content-Type: application/json

{
    "username": "rohith",
    "password": "12345"
}
""",
"""GETusers100""",
"""GET /users/100"""
]
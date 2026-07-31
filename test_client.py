import requests
import time

session = requests.Session()

url = "http://127.0.0.1:8000/users/1"

headers = {
    "Authorization": "Bearer T1"
}

while True:
    try:
        r = session.get(url, headers=headers, timeout=10)
        print(f"Status: {r.status_code}")
        print(r.text)
    except Exception as e:
        print("FAILED:", e)

    time.sleep(2)
import socket, json

SOCK_PATH = "/tmp/api-sentinel.sock"

def block_flow(saddr: int, daddr: int, sport: int, dport: int, ttl_ms: int = 30000): # 30000 ms = 30 seconds
    if saddr is None or daddr is None:
        return
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(SOCK_PATH)
            cmd = {"saddr": saddr, "daddr": daddr, "sport": sport, "dport": dport, "ttl_ms": ttl_ms}
            s.sendall((json.dumps(cmd) + "\n").encode())
    except OSError as e:
        print(f"[Enforcer] socket error: {e}")
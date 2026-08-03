from dataclasses import dataclass, field
import socket
import struct


def ip_to_str(addr):
    if addr is None:
        return None
    return socket.inet_ntoa(struct.pack("!I", addr))


@dataclass
class ParsedRequest:

    method: str
    path: str
    query_parameters: dict
    http_version: str
    headers: dict
    body: dict | str

    conn_id: int = None
    client_ip: str = None
    server_ip: str = None
    sport: int = None
    dport: int = None

    risk_score: int = 0
    alerts: list = field(default_factory=list)
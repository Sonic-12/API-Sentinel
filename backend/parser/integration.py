import json
import sys
from parser.decoder import decode_payload
from parser.request_parser import parse_request


def process_packet(packet_json):
    try:
        packet = json.loads(packet_json)
    except json.JSONDecodeError:
        return
    if packet.get("dir") != "request":
        return
    payload_hex = packet.get("payload_hex")
    if not payload_hex:
        return
    decoded_request = decode_payload(payload_hex)
    if not decoded_request:
        return

    saddr = packet.get("saddr")
    daddr = packet.get("daddr")
    sport = packet.get("sport")
    dport = packet.get("dport")

    try:
        parse_request(
            decoded_request,
            conn_id=packet.get("conn_id"),
            saddr=saddr,
            daddr=daddr,
            sport=sport,
            dport=dport,
        )
    except Exception as e:
        print(f"[Parser Error] {e}")


if __name__ == "__main__":
    while True:
        try:
            packet_json = input()
            process_packet(packet_json)
        except EOFError:
            break
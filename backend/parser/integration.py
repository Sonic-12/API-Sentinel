import json

from parser.decoder import decode_payload
from parser.request_parser import parse_request


def process_packet(packet_json):
    # Step 1: Parse JSON safely
    try:
        packet = json.loads(packet_json)
    except json.JSONDecodeError:
        return

    # Step 2: Process only HTTP requests
    if packet.get("dir") != "request":
        return

    # Step 3: Get payload
    payload_hex = packet.get("payload_hex")
    if not payload_hex:
        return

    # Step 4: Decode hex to HTTP request
    decoded_request = decode_payload(payload_hex)
    if not decoded_request:
        return

    # Step 5: Parse HTTP request safely
    try:
        parse_request(decoded_request)
    except Exception as e:
        print(f"[Parser Error] {e}")


if __name__ == "__main__":
    while True:
        try:
            packet_json = input()
            process_packet(packet_json)
        except EOFError:
            break
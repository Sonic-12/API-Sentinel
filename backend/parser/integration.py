import json

from parser.decoder import decode_payload
from parser.request_parser import parse_request

def process_packet(packet_json):
    packet = json.loads(packet_json)

    if packet["dir"] != "request":
        return

    payload_hex = packet["payload_hex"]

    decoded_request = decode_payload(payload_hex)

    if decoded_request:
        parse_request(decoded_request)

if __name__ == "__main__":
    while True:
        try:
            packet_json = input()
            process_packet(packet_json)
        except EOFError:
            break
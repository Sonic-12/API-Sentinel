from parser.decoder import decode_payload
from parser.request_parser import parse_request

payload_hex = "474554202f6865616c746820485454502f312e310d0a486f73743a206c6f63616c686f73740d0a0d0a"

decoded_request = decode_payload(payload_hex)

print(decoded_request)
parse_request(decoded_request)
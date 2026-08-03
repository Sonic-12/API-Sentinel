def decode_payload(payload_hex):

    try:
        decoded_data = bytes.fromhex(payload_hex).decode("utf-8", errors="replace")
        return decoded_data

    except ValueError:
        print("Invalid hexadecimal payload.")
        return None
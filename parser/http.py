from parser.packet import Packet

_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ", b"CONNECT ")


def parse_http(p: Packet) -> None:
    if p.protocol != "TCP" or len(p.payload) < 4:
        return

    payload = p.payload

    if any(payload.startswith(m) for m in _METHODS):
        _parse_request(p, payload)
    elif payload.startswith(b"HTTP/"):
        _parse_response(p, payload)


def _parse_request(p: Packet, payload: bytes) -> None:
    try:
        first_line_end = payload.index(b"\r\n")
        first_line = payload[:first_line_end].decode("utf-8", errors="replace")
        parts = first_line.split(" ", 2)
        if len(parts) >= 2:
            p.http_method = parts[0]
            p.http_path = parts[1]

        headers = payload[first_line_end + 2:]
        for line in headers.split(b"\r\n"):
            if line.lower().startswith(b"host:"):
                p.http_host = line[5:].strip().decode("utf-8", errors="replace")
                break
    except (ValueError, UnicodeDecodeError):
        pass


def _parse_response(p: Packet, payload: bytes) -> None:
    try:
        first_line_end = payload.index(b"\r\n")
        first_line = payload[:first_line_end].decode("utf-8", errors="replace")
        parts = first_line.split(" ", 2)
        if len(parts) >= 2:
            p.http_status = int(parts[1])
    except (ValueError, UnicodeDecodeError):
        pass

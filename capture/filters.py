from typing import List


def build_bpf(ports: List[int] = None, protocols: List[str] = None, capture_dns: bool = False) -> str:
    parts = []

    if capture_dns:
        parts.append("port 53")

    for p in (ports or []):
        parts.append(f"port {p}")

    for proto in (protocols or []):
        if proto.lower() in ("tcp", "udp", "icmp"):
            parts.append(proto.lower())

    if not parts:
        return ""
    return " or ".join(parts)


def default_filter() -> str:
    return build_bpf(protocols=["tcp", "udp", "icmp"], capture_dns=True)

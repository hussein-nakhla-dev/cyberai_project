"""Single-attempt TCP connect check of common ports (no banners, no exploits)."""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

from ..config import PORT_TIMEOUT
from ..models import Observation
from ..rules import make_finding
from .base import CheckOutput, ScanContext

PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 80: "HTTP", 110: "POP3",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 1433: "MSSQL", 3306: "MySQL",
    3389: "RDP", 5432: "PostgreSQL", 5900: "VNC", 6379: "Redis",
    8080: "HTTP-Alt", 8443: "HTTPS-Alt", 9200: "Elasticsearch",
    11211: "Memcached", 27017: "MongoDB",
}
RISKY = {21, 23, 445, 1433, 3306, 3389, 5432, 5900, 6379, 9200, 11211, 27017}


def _is_open(ip: str, port: int) -> bool:
    try:
        with socket.create_connection((ip, port), timeout=PORT_TIMEOUT):
            return True
    except OSError:
        return False


def check_ports(ctx: ScanContext) -> CheckOutput:
    if not ctx.port_scan:
        return CheckOutput(status="skipped", detail="port check disabled")
    ip = ctx.target.ips[0]
    with ThreadPoolExecutor(max_workers=len(PORTS)) as pool:
        results = dict(zip(PORTS, pool.map(lambda p: _is_open(ip, p), PORTS)))
    open_ports = [p for p, ok in results.items() if ok]

    out = CheckOutput()
    out.observations.append(Observation("scanned_ip", ip))
    out.observations.append(Observation(
        "open_ports", ", ".join(f"{p}/{PORTS[p]}" for p in open_ports) or "none"))
    for port in open_ports:
        if port in RISKY:
            out.findings.append(make_finding(
                "PORT-RISKY", ctx.target.host, "Port-Checker",
                {"port": port, "service": PORTS[port], "ip": ip},
                status="Observed", confidence=0.75, key=str(port), timestamp=ctx.timestamp,
            ))
    return out

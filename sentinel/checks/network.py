"""Network exposure checks based on /proc (no external commands)."""

from __future__ import annotations

import socket
import struct
from pathlib import Path

from sentinel.checks.base import Check
from sentinel.core import Severity

# TCP states from the kernel; 0A == LISTEN.
_LISTEN = "0A"

# Ports that are risky to expose beyond localhost.
RISKY_PORTS = {
    23: ("Telnet", Severity.CRITICAL),
    21: ("FTP", Severity.HIGH),
    3389: ("RDP", Severity.HIGH),
    3306: ("MySQL", Severity.HIGH),
    5432: ("PostgreSQL", Severity.HIGH),
    6379: ("Redis", Severity.HIGH),
    27017: ("MongoDB", Severity.HIGH),
    9200: ("Elasticsearch", Severity.HIGH),
    5900: ("VNC", Severity.HIGH),
    2375: ("Docker API", Severity.CRITICAL),
    11211: ("Memcached", Severity.HIGH),
}


def _hex_to_ip_port(hexpair: str, ipv6: bool):
    addr, port_hex = hexpair.split(":")
    port = int(port_hex, 16)
    if ipv6:
        raw = bytes.fromhex(addr)
        # /proc stores each 32-bit word little-endian.
        words = struct.unpack("<4I", raw)
        ip = socket.inet_ntop(socket.AF_INET6, struct.pack(">4I", *words))
    else:
        ip = socket.inet_ntoa(struct.pack("<I", int(addr, 16)))
    return ip, port


def _listening_sockets():
    """Yield (ip, port) for every listening TCP socket, or None if /proc absent."""
    results = []
    found_proc = False
    for name, ipv6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
        p = Path(name)
        if not p.exists():
            continue
        found_proc = True
        try:
            lines = p.read_text().splitlines()[1:]
        except OSError:
            continue
        for line in lines:
            cols = line.split()
            if len(cols) < 4 or cols[3] != _LISTEN:
                continue
            try:
                ip, port = _hex_to_ip_port(cols[1], ipv6)
            except (ValueError, struct.error, OSError):
                continue
            results.append((ip, port))
    return results if found_proc else None


def _is_public_bind(ip: str) -> bool:
    return ip not in ("127.0.0.1", "::1", "0.0.0.0000") and not ip.startswith("127.")


class ListeningServices(Check):
    id = "net.listening"
    category = "Network"
    title = "Listening services"
    posix_only = True

    def run(self):
        socks = _listening_sockets()
        if socks is None:
            yield self.finding(Severity.INFO, "No /proc/net data available",
                               detail="Network exposure check is unavailable here.")
            return
        public = sorted({(ip, port) for ip, port in socks if _is_public_bind(ip)})
        risky_hits = []
        for ip, port in public:
            if port in RISKY_PORTS:
                name, sev = RISKY_PORTS[port]
                risky_hits.append((ip, port, name, sev))
        for ip, port, name, sev in risky_hits:
            yield self.finding(
                sev,
                f"{name} exposed on {ip}:{port}",
                detail="This service is reachable from outside localhost.",
                recommendation="Bind to 127.0.0.1 or firewall the port.",
                evidence=(f"{ip}:{port}",),
            )
        externally = [f"{ip}:{port}" for ip, port in public]
        if externally:
            yield self.finding(
                Severity.INFO if not risky_hits else Severity.LOW,
                f"{len(externally)} service(s) listening on non-loopback addresses",
                recommendation="Confirm every externally-bound port is intended.",
                evidence=tuple(externally[:12]),
            )
        else:
            yield self.ok("No services bound to external interfaces.")

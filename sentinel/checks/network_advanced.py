"""Advanced network checks: promiscuous sniffers, established connections, DNS and hosts."""

from __future__ import annotations

import os
from pathlib import Path

from sentinel.checks.base import Check, read_text
from sentinel.checks.network import _hex_to_ip_port, _is_public_bind
from sentinel.core import Severity

# State 01 in /proc/net/tcp is ESTABLISHED
_ESTABLISHED = "01"

HIGH_VALUE_DOMAINS = (
    "google.com",
    "github.com",
    "microsoft.com",
    "apple.com",
    "cloudflare.com",
    "amazon.com",
    "paypal.com",
    "bank",
)


class PromiscuousInterfaces(Check):
    """Detect network interfaces operating in promiscuous mode (IFF_PROMISC)."""

    id = "net.promiscuous"
    category = "Network"
    title = "Promiscuous network interfaces"
    posix_only = True

    def run(self):
        net_dir = Path("/sys/class/net")
        if not net_dir.is_dir():
            return

        promisc_ifaces = []
        try:
            for iface in net_dir.iterdir():
                flags_file = iface / "flags"
                if flags_file.exists():
                    val = read_text(flags_file)
                    if val:
                        try:
                            flags = int(val.strip(), 16)
                            # IFF_PROMISC is 0x100 (256)
                            if flags & 0x100:
                                promisc_ifaces.append(iface.name)
                        except ValueError:
                            continue
        except OSError:
            pass

        if promisc_ifaces:
            yield self.finding(
                Severity.HIGH,
                f"Interface(s) in promiscuous mode: {', '.join(promisc_ifaces)}",
                detail="Promiscuous mode allows capturing all packets on the network segment (packet sniffer active).",
                recommendation="Check if tcpdump, Wireshark, or an unauthorized sniffer is running.",
                evidence=tuple(promisc_ifaces),
            )
        else:
            yield self.ok("No network interfaces operating in promiscuous mode.")


class HostsHijackingCheck(Check):
    """Detect suspicious redirections in /etc/hosts for major internet services."""

    id = "net.hosts_hijack"
    category = "Network"
    title = "Hosts file DNS redirection"
    posix_only = True

    def run(self):
        hosts_file = Path("/etc/hosts")
        content = read_text(hosts_file)
        if not content:
            yield self.ok("Cannot read /etc/hosts.")
            return

        hijacked = []
        for line_no, line in enumerate(content.splitlines(), start=1):
            clean = line.strip()
            if not clean or clean.startswith("#"):
                continue
            parts = clean.split()
            if len(parts) >= 2:
                ip = parts[0]
                domains = parts[1:]
                for d in domains:
                    for hv in HIGH_VALUE_DOMAINS:
                        if hv in d.lower():
                            hijacked.append((line_no, ip, d))

        if hijacked:
            for line_no, ip, domain in hijacked:
                yield self.finding(
                    Severity.HIGH,
                    f"Domain override in /etc/hosts line {line_no}: {domain} -> {ip}",
                    detail="Overriding major internet domains in /etc/hosts is commonly used for phishing or update blocking.",
                    recommendation=f"Review and remove suspicious entry on line {line_no} of /etc/hosts.",
                    evidence=(f"line={line_no}", f"domain={domain}", f"ip={ip}"),
                )
        else:
            yield self.ok("/etc/hosts contains no suspicious overrides for high-value domains.")


class EstablishedOutboundConnections(Check):
    """Inspect active outbound ESTABLISHED TCP connections via /proc."""

    id = "net.established_connections"
    category = "Network"
    title = "Active outbound network connections"
    posix_only = True

    def run(self):
        established = []
        for name, ipv6 in (("/proc/net/tcp", False), ("/proc/net/tcp6", True)):
            p = Path(name)
            if not p.exists():
                continue
            try:
                lines = p.read_text().splitlines()[1:]
            except OSError:
                continue

            for line in lines:
                cols = line.split()
                if len(cols) < 4 or cols[3] != _ESTABLISHED:
                    continue
                try:
                    local_ip, local_port = _hex_to_ip_port(cols[1], ipv6)
                    remote_ip, remote_port = _hex_to_ip_port(cols[2], ipv6)
                except Exception:
                    continue

                if _is_public_bind(remote_ip):
                    established.append(f"{local_ip}:{local_port} -> {remote_ip}:{remote_port}")

        if established:
            yield self.finding(
                Severity.INFO,
                f"{len(established)} active outbound connection(s) established",
                detail="Snapshot of active non-loopback network sessions.",
                recommendation="Review connected remote endpoints to ensure all connections belong to legitimate software.",
                evidence=tuple(established[:12]),
            )
        else:
            yield self.ok("No active external TCP connections established.")

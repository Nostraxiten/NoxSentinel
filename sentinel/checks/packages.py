"""Package manager integrity, kernel CVE baseline, and security update status."""

from __future__ import annotations

import os
import platform
import re
from pathlib import Path

from sentinel.checks.base import Check, read_text
from sentinel.core import Severity


def _parse_version(release_str: str) -> tuple[int, ...]:
    """Parse kernel version digits from a release string like '5.10.0-8-amd64'."""
    match = re.match(r"^(\d+)\.(\d+)(?:\.(\d+))?", release_str)
    if not match:
        return (0, 0, 0)
    major, minor, patch = match.groups()
    return (int(major), int(minor), int(patch or 0))


class KernelCveBaseline(Check):
    """Check running Linux kernel version against prominent local privilege escalation CVE baselines."""

    id = "pkg.kernel_cve"
    category = "Packages"
    title = "Kernel vulnerability baseline"
    posix_only = True

    def run(self):
        rel = platform.release()
        ver = _parse_version(rel)
        if ver == (0, 0, 0):
            yield self.ok(f"Kernel release '{rel}' could not be parsed.")
            return

        cves = []
        # Dirty COW: CVE-2016-5195 (Linux 2.6.22 through 4.8.3)
        if (2, 6, 22) <= ver < (4, 8, 3):
            cves.append(("Dirty COW (CVE-2016-5195)", "Allows local privilege escalation via copy-on-write race."))

        # Dirty Pipe: CVE-2022-0847 (Linux 5.8 through 5.16.11, 5.15.25, 5.10.102)
        if (5, 8, 0) <= ver < (5, 10, 102) or (5, 11, 0) <= ver < (5, 15, 25) or (5, 16, 0) <= ver < (5, 16, 11):
            cves.append(("Dirty Pipe (CVE-2022-0847)", "Allows unauthorized overwriting of read-only files and root elevation."))

        if cves:
            for name, desc in cves:
                yield self.finding(
                    Severity.CRITICAL,
                    f"Kernel {rel} is vulnerable to {name}",
                    detail=f"{desc} Running kernel version {ver} is below the patched baseline.",
                    recommendation="Update system kernel and reboot: apt update && apt upgrade linux-image-generic",
                    evidence=(f"kernel={rel}", f"matched={name}"),
                )
        else:
            yield self.ok(f"Kernel {rel} is outside known critical historical vulnerability windows.")


class AutomaticUpdatesConfig(Check):
    """Check if automatic security updates are configured on the system."""

    id = "pkg.auto_updates"
    category = "Packages"
    title = "Automatic security updates"
    posix_only = True

    def run(self):
        # 1. Debian/Ubuntu unattended-upgrades
        unattended = Path("/etc/apt/apt.conf.d/20auto-upgrades")
        if unattended.exists():
            content = read_text(unattended)
            if content and 'Unattended-Upgrade "1"' in content:
                yield self.ok("Automatic security updates (unattended-upgrades) are enabled.")
                return

        # 2. RHEL/Fedora dnf-automatic
        dnf_auto = Path("/etc/dnf/automatic.conf")
        if dnf_auto.exists():
            content = read_text(dnf_auto)
            if content and "apply_updates = yes" in content.lower():
                yield self.ok("Automatic updates (dnf-automatic) are enabled.")
                return

        # If neither is found or configured on a standard Linux distribution
        if Path("/etc/debian_version").exists() or Path("/etc/fedora-release").exists():
            yield self.finding(
                Severity.LOW,
                "Automatic security updates do not appear to be active",
                detail="Systems without automated security patching may remain vulnerable to newly published CVEs.",
                recommendation="Install and enable unattended-upgrades (Debian/Ubuntu) or dnf-automatic (Fedora/RHEL).",
            )
        else:
            yield self.ok("No standard package auto-update mechanism detected for this distribution.")

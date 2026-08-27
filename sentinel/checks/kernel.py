"""Kernel and environment hardening checks via sysctl-style /proc entries."""

from __future__ import annotations

import os
from pathlib import Path

from sentinel.checks.base import Check, read_text
from sentinel.core import Severity


class SysctlHardening(Check):
    id = "kernel.sysctl"
    category = "Kernel"
    title = "Kernel hardening flags"
    posix_only = True

    # path -> (expected_value, severity, human name, recommendation)
    RULES = {
        "/proc/sys/kernel/randomize_va_space": (
            "2", Severity.MEDIUM, "ASLR",
            "Set kernel.randomize_va_space=2."),
        "/proc/sys/net/ipv4/conf/all/rp_filter": (
            "1", Severity.LOW, "Reverse-path filtering",
            "Set net.ipv4.conf.all.rp_filter=1."),
        "/proc/sys/net/ipv4/tcp_syncookies": (
            "1", Severity.LOW, "TCP SYN cookies",
            "Set net.ipv4.tcp_syncookies=1."),
    }

    def run(self):
        clean = True
        for path, (expected, sev, name, rec) in self.RULES.items():
            value = read_text(path)
            if value is None:
                continue
            value = value.strip()
            if value != expected:
                clean = False
                yield self.finding(
                    sev,
                    f"{name} not at recommended value ({value})",
                    detail=f"Expected {expected} at {path}.",
                    recommendation=rec,
                )
        if clean:
            yield self.ok("Kernel hardening flags are at recommended values.")


class DangerousPathEntries(Check):
    id = "env.path"
    category = "Environment"
    title = "Executable search path"
    posix_only = True

    def run(self):
        raw = os.environ.get("PATH", "")
        entries = raw.split(os.pathsep)
        issues = []
        for entry in entries:
            if entry in ("", "."):
                issues.append(("HIGH", f"'{entry or 'empty'}' means the current directory"))
                continue
            p = Path(entry)
            if not p.is_absolute():
                issues.append(("MEDIUM", f"relative entry '{entry}'"))
            elif p.is_dir():
                try:
                    if p.stat().st_mode & 0o002:
                        issues.append(("HIGH", f"world-writable '{entry}'"))
                except OSError:
                    pass
        if issues:
            worst = Severity.HIGH if any(s == "HIGH" for s, _ in issues) else Severity.MEDIUM
            yield self.finding(
                worst,
                f"{len(issues)} risky entry(ies) in $PATH",
                detail="Writable or relative PATH entries enable binary hijacking.",
                recommendation="Use only absolute, non-writable directories in PATH.",
                evidence=tuple(msg for _sev, msg in issues),
            )
        else:
            yield self.ok("$PATH contains only safe absolute directories.")


class UmaskCheck(Check):
    id = "env.umask"
    category = "Environment"
    title = "Default umask"
    posix_only = True

    def run(self):
        current = os.umask(0o022)
        os.umask(current)  # restore immediately
        if current & 0o002:
            yield self.finding(
                Severity.LOW,
                f"umask {current:04o} creates world-writable files",
                recommendation="Use a umask of 022 or 027.",
            )
        else:
            yield self.ok(f"umask {current:04o} is safe.")

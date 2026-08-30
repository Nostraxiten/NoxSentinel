"""Persistence mechanism checks: cron, systemd, shell startup, and dynamic linkers."""

from __future__ import annotations

import os
import re
from pathlib import Path

from sentinel.checks.base import Check, read_text
from sentinel.core import Severity

# Patterns that indicate suspicious or backdoor commands
SUSPICIOUS_CMD_PATTERNS = (
    (re.compile(r"(curl|wget)\s+[^|\n]+?\|\s*(ba)?sh", re.IGNORECASE), "Pipe from internet to shell (curl|sh)"),
    (re.compile(r"/dev/tcp/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d+", re.IGNORECASE), "Direct /dev/tcp reverse shell"),
    (re.compile(r"nc\s+.*-e\s+/bin/(ba)?sh", re.IGNORECASE), "Netcat executable shell (-e /bin/sh)"),
    (re.compile(r"base64\s+-d.*\|\s*(ba)?sh", re.IGNORECASE), "Base64 decode piped to shell"),
    (re.compile(r"(/tmp/|/var/tmp/|/dev/shm/)[^\s]+\.(sh|elf|bin|py|pl)", re.IGNORECASE), "Execution directly from temporary directories"),
    (re.compile(r"python.*-c\s+['\"].*import\s+(socket|subprocess).*['\"]", re.IGNORECASE), "Inline Python reverse shell snippet"),
)


class SuspiciousCronCommands(Check):
    """Detect suspicious commands (reverse shells, download-and-execute) in cron."""

    id = "persist.cron_commands"
    category = "Persistence"
    title = "Suspicious cron commands"
    posix_only = True

    CRON_LOCATIONS = (
        "/etc/crontab",
        "/etc/cron.d",
        "/etc/cron.daily",
        "/etc/cron.hourly",
        "/etc/cron.weekly",
        "/etc/cron.monthly",
        "/var/spool/cron/crontabs",
        "/var/spool/cron",
    )

    def run(self):
        findings_list = []

        def inspect_file(fp: Path):
            content = read_text(fp)
            if not content:
                return
            for line_no, line in enumerate(content.splitlines(), start=1):
                clean = line.strip()
                if not clean or clean.startswith("#"):
                    continue
                for pattern, desc in SUSPICIOUS_CMD_PATTERNS:
                    if pattern.search(clean):
                        findings_list.append((str(fp), line_no, desc, clean[:80]))

        for loc in self.CRON_LOCATIONS:
            p = Path(loc)
            if p.is_file():
                inspect_file(p)
            elif p.is_dir():
                try:
                    for entry in p.iterdir():
                        if entry.is_file():
                            inspect_file(entry)
                except OSError:
                    continue

        if findings_list:
            for filepath, line_no, desc, snippet in findings_list:
                yield self.finding(
                    Severity.CRITICAL,
                    f"Suspicious cron job in {filepath}:{line_no}",
                    detail=f"Matched: {desc}. Snippet: {snippet}",
                    recommendation=f"Inspect and remove malicious entries from {filepath}.",
                    evidence=(f"file={filepath}", f"line={line_no}", f"snippet={snippet}"),
                )
        else:
            yield self.ok("No suspicious commands or download pipelines found in cron jobs.")


class LdPreloadCheck(Check):
    """Detect dynamic library preloading via /etc/ld.so.preload or environment."""

    id = "persist.ld_preload"
    category = "Persistence"
    title = "Dynamic linker preloading (LD_PRELOAD)"
    posix_only = True

    def run(self):
        preload_file = Path("/etc/ld.so.preload")
        if preload_file.exists():
            content = read_text(preload_file)
            if content and content.strip():
                yield self.finding(
                    Severity.CRITICAL,
                    "/etc/ld.so.preload is present and non-empty",
                    detail=f"Preloaded libraries: {content.strip()}. This hook intercepts calls for every binary on the system.",
                    recommendation="Review the contents of /etc/ld.so.preload and remove unauthorized shared libraries.",
                    evidence=(f"libraries={content.strip()}",),
                )
                return

        env_preload = os.environ.get("LD_PRELOAD")
        if env_preload:
            yield self.finding(
                Severity.HIGH,
                f"LD_PRELOAD environment variable is set ({env_preload})",
                detail="LD_PRELOAD forces custom libraries into processes and is often used by rootkits or userland hooks.",
                recommendation="Unset LD_PRELOAD if not intentionally configured for debugging.",
                evidence=(f"LD_PRELOAD={env_preload}",),
            )
        else:
            yield self.ok("No global LD_PRELOAD or /etc/ld.so.preload configuration detected.")


class ShellProfileInjections(Check):
    """Detect suspicious commands and pipelines in shell startup scripts."""

    id = "persist.shell_profiles"
    category = "Persistence"
    title = "Shell profile persistence"
    posix_only = True

    GLOBAL_FILES = (
        "/etc/profile",
        "/etc/bash.bashrc",
        "/etc/zsh/zprofile",
        "/etc/zsh/zshrc",
        "/etc/environment",
    )

    USER_FILES = (
        ".bashrc",
        ".bash_profile",
        ".bash_login",
        ".profile",
        ".zshrc",
        ".zprofile",
    )

    def run(self):
        targets = [Path(p) for p in self.GLOBAL_FILES]
        home = Path.home()
        for u in self.USER_FILES:
            targets.append(home / u)

        detected = []
        for target in targets:
            content = read_text(target)
            if not content:
                continue
            for line_no, line in enumerate(content.splitlines(), start=1):
                clean = line.strip()
                if not clean or clean.startswith("#"):
                    continue
                for pattern, desc in SUSPICIOUS_CMD_PATTERNS:
                    if pattern.search(clean):
                        detected.append((str(target), line_no, desc, clean[:80]))

        if detected:
            for filepath, line_no, desc, snippet in detected:
                yield self.finding(
                    Severity.HIGH,
                    f"Suspicious code in startup file {filepath}:{line_no}",
                    detail=f"Matched: {desc}. Snippet: {snippet}",
                    recommendation=f"Review and clean {filepath}.",
                    evidence=(f"file={filepath}", f"line={line_no}", f"snippet={snippet}"),
                )
        else:
            yield self.ok("Shell profile and startup files contain no known suspicious hooks.")


class SystemdSuspiciousServices(Check):
    """Detect systemd service units executing binaries from suspicious paths."""

    id = "persist.systemd_services"
    category = "Persistence"
    title = "Systemd service definitions"
    posix_only = True

    UNIT_DIRS = (
        "/etc/systemd/system",
        "/lib/systemd/system",
        "/usr/lib/systemd/system",
    )

    def run(self):
        flagged = []
        for d in self.UNIT_DIRS:
            p = Path(d)
            if not p.is_dir():
                continue
            try:
                for entry in p.glob("*.service"):
                    content = read_text(entry)
                    if not content:
                        continue
                    for line in content.splitlines():
                        line_s = line.strip()
                        if line_s.startswith("ExecStart=") or line_s.startswith("ExecStartPre="):
                            for pattern, desc in SUSPICIOUS_CMD_PATTERNS:
                                if pattern.search(line_s):
                                    flagged.append((entry.name, desc, line_s[:80]))
                                    break
            except OSError:
                continue

        if flagged:
            for service_name, desc, exec_line in flagged:
                yield self.finding(
                    Severity.CRITICAL,
                    f"Suspicious systemd service: {service_name}",
                    detail=f"Matched {desc}. Definition: {exec_line}",
                    recommendation=f"Inspect systemctl status {service_name} and disable it if unknown.",
                    evidence=(f"unit={service_name}", f"exec={exec_line}"),
                )
        else:
            yield self.ok("Systemd unit files do not execute binaries from temporary paths or pipelines.")

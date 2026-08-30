"""Forensic indicators and anti-forensics artifact checks."""

from __future__ import annotations

import os
import stat
import time
from pathlib import Path

from sentinel.checks.base import Check, mode_string, read_text
from sentinel.core import Severity


class LogTamperingCheck(Check):
    """Detect truncated or deleted system authentication and audit logs."""

    id = "forensic.log_tampering"
    category = "Forensics"
    title = "System log file integrity"
    posix_only = True

    CRITICAL_LOGS = (
        "/var/log/auth.log",
        "/var/log/secure",
        "/var/log/audit/audit.log",
        "/var/log/syslog",
        "/var/log/messages",
        "/var/log/wtmp",
        "/var/log/btmp",
        "/var/log/lastlog",
    )

    def run(self):
        truncated = []
        for log_path in self.CRITICAL_LOGS:
            p = Path(log_path)
            if not p.exists():
                continue
            try:
                st = p.stat()
                # If a major active log exists but is 0 bytes, it may have been truncated/wiped
                if st.st_size == 0 and p.name in ("auth.log", "secure", "audit.log"):
                    truncated.append(log_path)
            except OSError:
                continue

        if truncated:
            yield self.finding(
                Severity.HIGH,
                f"{len(truncated)} critical security log(s) are completely empty (0 bytes)",
                detail="Security logs being 0 bytes can indicate anti-forensics wiping (e.g. cat /dev/null > log).",
                recommendation="Investigate why these logs are empty and check logrotate configuration.",
                evidence=tuple(truncated),
            )
        else:
            yield self.ok("Security log files exist with active content.")


class HistoryFileTampering(Check):
    """Detect disabled command history, truncated history, or links to /dev/null."""

    id = "forensic.shell_history"
    category = "Forensics"
    title = "Shell command history tampering"
    posix_only = True

    HISTORY_FILES = (".bash_history", ".zsh_history", ".sh_history")

    def run(self):
        home = Path.home()
        issues = []

        for hf in self.HISTORY_FILES:
            target = home / hf
            if target.is_symlink():
                try:
                    dest = os.readlink(target)
                    if "/dev/null" in dest:
                        issues.append(f"{hf} -> symlinked to {dest} (history disabled)")
                except OSError:
                    continue
            elif target.is_file():
                try:
                    st = target.stat()
                    # 0 byte history file when shell has been used
                    if st.st_size == 0:
                        issues.append(f"{hf} is 0 bytes (cleared)")
                except OSError:
                    continue

        if issues:
            yield self.finding(
                Severity.MEDIUM,
                f"Suspicious command history status: {', '.join(issues)}",
                detail="Redirecting history to /dev/null or clearing it hides attacker actions.",
                recommendation="Ensure shell history is enabled for accountability (HISTFILE).",
                evidence=tuple(issues),
            )
        else:
            yield self.ok("Shell history files are active and not redirected to /dev/null.")


class FutureTimestampFiles(Check):
    """Detect timestomping where file mtimes are set in the future."""

    id = "forensic.timestomping"
    category = "Forensics"
    title = "Files with future timestamps"
    posix_only = True

    SCAN_PATHS = ("/bin", "/sbin", "/usr/bin", "/etc", "/tmp")

    def run(self):
        now = time.time()
        # Tolerance of 300 seconds (5 mins) for minor clock skew
        future_cutoff = now + 300
        anomalies = []

        for root in self.SCAN_PATHS:
            p = Path(root)
            if not p.is_dir():
                continue
            try:
                for entry in os.scandir(root):
                    try:
                        st = entry.stat(follow_symlinks=False)
                        if st.st_mtime > future_cutoff:
                            anomalies.append(f"{entry.path} (mtime {int(st.st_mtime - now)}s in future)")
                    except OSError:
                        continue
            except OSError:
                continue

        if anomalies:
            yield self.finding(
                Severity.MEDIUM,
                f"{len(anomalies)} file(s) with future modification timestamps (timestomping)",
                detail="Setting file timestamps in the future is a known anti-forensics technique to evade chronological sorting.",
                recommendation="Investigate the origin and integrity of these files.",
                evidence=tuple(anomalies[:10]),
            )
        else:
            yield self.ok("No files with timestamps in the future found in system paths.")


class TmpStickyBitCheck(Check):
    """Ensure /tmp and /var/tmp directories have the sticky bit (0o1000) set."""

    id = "forensic.tmp_sticky"
    category = "Forensics"
    title = "Sticky bit on world-writable temporary directories"
    posix_only = True

    DIRS = ("/tmp", "/var/tmp")

    def run(self):
        missing_sticky = []
        for d in self.DIRS:
            p = Path(d)
            if not p.is_dir():
                continue
            try:
                mode = p.stat().st_mode
                perms = stat.S_IMODE(mode)
                # World-writable (0o002) without sticky bit (0o1000)
                if (perms & 0o002) and not (perms & 0o1000):
                    missing_sticky.append((d, mode_string(perms)))
            except OSError:
                continue

        if missing_sticky:
            for d, perms_str in missing_sticky:
                yield self.finding(
                    Severity.HIGH,
                    f"Temporary directory {d} lacks sticky bit ({perms_str})",
                    detail="Without the sticky bit, any user can delete or replace other users' files in this directory.",
                    recommendation=f"chmod +t {d} (chmod 1777 {d})",
                    evidence=(f"dir={d}", f"mode={perms_str}"),
                )
        else:
            yield self.ok("World-writable temporary directories have sticky bits properly set.")

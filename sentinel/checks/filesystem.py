"""Filesystem hardening checks: sensitive-file permissions and risky bits."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from sentinel.checks.base import Check, mode_string
from sentinel.core import Severity

# Files that should never be world-readable/writable, with the max mode
# that is considered safe.
SENSITIVE_FILES = {
    "/etc/shadow": 0o640,
    "/etc/gshadow": 0o640,
    "/etc/passwd": 0o644,
    "/etc/group": 0o644,
    "/etc/sudoers": 0o440,
}


class SensitiveFilePermissions(Check):
    id = "fs.sensitive_perms"
    category = "Filesystem"
    title = "Sensitive file permissions"
    posix_only = True

    def run(self):
        clean = True
        for path, max_mode in SENSITIVE_FILES.items():
            p = Path(path)
            if not p.exists():
                continue
            try:
                mode = p.stat().st_mode
            except OSError:
                continue
            perms = stat.S_IMODE(mode)
            if perms & ~max_mode:
                clean = False
                world = "world-writable" if perms & 0o002 else "over-permissive"
                sev = Severity.CRITICAL if perms & 0o002 else Severity.HIGH
                yield self.finding(
                    sev,
                    f"{path} is {world} ({mode_string(perms)})",
                    detail=f"Expected at most {mode_string(max_mode)}.",
                    recommendation=f"chmod {mode_string(max_mode)} {path}",
                    evidence=(f"mode={mode_string(perms)}",),
                )
        if clean:
            yield self.ok("Sensitive files carry safe permissions.")


class HomeDirExposure(Check):
    id = "fs.home_perms"
    category = "Filesystem"
    title = "Home directory exposure"
    posix_only = True

    def run(self):
        home = Path.home()
        try:
            perms = stat.S_IMODE(home.stat().st_mode)
        except OSError:
            return
        if perms & 0o002:
            yield self.finding(
                Severity.HIGH,
                f"Home directory {home} is world-writable ({mode_string(perms)})",
                recommendation=f"chmod 750 {home}",
            )
        elif perms & 0o007:
            yield self.finding(
                Severity.LOW,
                f"Home directory {home} is accessible to others ({mode_string(perms)})",
                recommendation=f"chmod 750 {home}",
            )
        else:
            yield self.ok(f"{home} is not exposed to other users.")


class SshKeyPermissions(Check):
    id = "fs.ssh_keys"
    category = "Filesystem"
    title = "SSH private key permissions"
    posix_only = True

    def run(self):
        ssh_dir = Path.home() / ".ssh"
        if not ssh_dir.is_dir():
            yield self.ok("No ~/.ssh directory present.")
            return
        exposed = []
        for key in ssh_dir.glob("id_*"):
            if key.name.endswith(".pub"):
                continue
            try:
                perms = stat.S_IMODE(key.stat().st_mode)
            except OSError:
                continue
            if perms & 0o077:
                exposed.append((key, perms))
        if exposed:
            for key, perms in exposed:
                yield self.finding(
                    Severity.HIGH,
                    f"Private key {key.name} readable by others ({mode_string(perms)})",
                    detail="OpenSSH refuses group/other-readable private keys.",
                    recommendation=f"chmod 600 {key}",
                )
        else:
            yield self.ok("Private keys are owner-only.")


class WorldWritableSearch(Check):
    id = "fs.world_writable"
    category = "Filesystem"
    title = "World-writable files in scope"
    posix_only = True

    #: Directories scanned for world-writable non-sticky entries.
    ROOTS = ("/etc", "/usr/local/bin", "/opt")
    LIMIT = 5000

    def run(self):
        offenders = []
        seen = 0
        for root in self.ROOTS:
            if not os.path.isdir(root):
                continue
            for dirpath, _dirs, files in os.walk(root, onerror=lambda e: None):
                for name in files:
                    seen += 1
                    if seen > self.LIMIT:
                        break
                    fp = os.path.join(dirpath, name)
                    try:
                        st = os.lstat(fp)
                    except OSError:
                        continue
                    if stat.S_ISLNK(st.st_mode):
                        continue
                    if st.st_mode & 0o002:
                        offenders.append(fp)
                if seen > self.LIMIT:
                    break
        if offenders:
            yield self.finding(
                Severity.MEDIUM,
                f"{len(offenders)} world-writable file(s) under system paths",
                detail="World-writable executables and configs can be tampered with.",
                recommendation="Review and remove the world-writable bit (chmod o-w).",
                evidence=tuple(offenders[:10]),
            )
        else:
            yield self.ok("No world-writable files found in scanned paths.")


class SuidBinaryInventory(Check):
    id = "fs.suid"
    category = "Filesystem"
    title = "SUID/SGID binary inventory"
    posix_only = True

    ROOTS = ("/usr/bin", "/usr/sbin", "/bin", "/sbin")
    # Well-known SUID binaries shipped by distributions.
    EXPECTED = {
        "sudo", "su", "passwd", "chsh", "chfn", "newgrp", "gpasswd",
        "mount", "umount", "ping", "pkexec", "fusermount", "fusermount3",
        "ntfs-3g", "sg", "unix_chkpwd", "polkit-agent-helper-1",
    }

    def run(self):
        unexpected = []
        total = 0
        for root in self.ROOTS:
            if not os.path.isdir(root):
                continue
            try:
                entries = os.scandir(root)
            except OSError:
                continue
            for entry in entries:
                try:
                    st = entry.stat(follow_symlinks=False)
                except OSError:
                    continue
                if st.st_mode & (stat.S_ISUID | stat.S_ISGID):
                    total += 1
                    if entry.name not in self.EXPECTED:
                        unexpected.append(entry.path)
        if unexpected:
            yield self.finding(
                Severity.MEDIUM,
                f"{len(unexpected)} unexpected SUID/SGID binary(ies)",
                detail=f"{total} SUID/SGID binaries total; the ones below are not "
                       "on the common baseline and deserve a look.",
                recommendation="Confirm each is intentional; drop SUID where not needed.",
                evidence=tuple(unexpected[:10]),
            )
        else:
            yield self.ok(f"{total} SUID/SGID binaries, all on the expected baseline.")

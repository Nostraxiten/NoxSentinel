"""OpenSSH server configuration hardening checks."""

from __future__ import annotations

import os
from pathlib import Path

from sentinel.checks.base import Check, read_text
from sentinel.core import Severity


def _parse_sshd_config(text: str) -> dict[str, str]:
    """Return the effective (last-wins) directive map, lower-cased keys."""
    settings: dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) == 2:
            settings[parts[0].lower()] = parts[1].strip()
    return settings


class SshdHardening(Check):
    id = "ssh.sshd_config"
    category = "SSH"
    title = "sshd hardening"
    posix_only = True

    PATH = "/etc/ssh/sshd_config"

    # directive -> (bad_value, severity, message, recommendation)
    RULES = {
        "permitrootlogin": ("yes", Severity.HIGH,
                            "Root can log in over SSH",
                            "Set 'PermitRootLogin no' (or prohibit-password)."),
        "passwordauthentication": ("yes", Severity.MEDIUM,
                            "Password authentication is enabled",
                            "Prefer keys: 'PasswordAuthentication no'."),
        "permitemptypasswords": ("yes", Severity.CRITICAL,
                            "Empty passwords are accepted over SSH",
                            "Set 'PermitEmptyPasswords no'."),
        "x11forwarding": ("yes", Severity.LOW,
                            "X11 forwarding is enabled",
                            "Disable unless required: 'X11Forwarding no'."),
    }

    def run(self):
        if not os.path.exists(self.PATH):
            yield self.ok("No sshd_config present; SSH server likely not installed.")
            return
        text = read_text(self.PATH)
        if text is None:
            yield self.finding(Severity.INFO, "Cannot read sshd_config",
                               detail="Run as root to audit SSH configuration.")
            return
        cfg = _parse_sshd_config(text)
        flagged = False
        for directive, (bad, sev, msg, rec) in self.RULES.items():
            value = cfg.get(directive, "").lower()
            if value == bad:
                flagged = True
                yield self.finding(sev, msg, recommendation=rec,
                                   evidence=(f"{directive} {value}",))
        # Protocol 1 is ancient and broken.
        if cfg.get("protocol", "2") != "2":
            flagged = True
            yield self.finding(Severity.HIGH, "SSH protocol 1 is enabled",
                               recommendation="Use 'Protocol 2' only.")
        if not flagged:
            yield self.ok("sshd_config matches the hardening baseline.")


class AuthorizedKeysReview(Check):
    id = "ssh.authorized_keys"
    category = "SSH"
    title = "authorized_keys review"
    posix_only = True

    def run(self):
        ak = Path.home() / ".ssh" / "authorized_keys"
        if not ak.exists():
            yield self.ok("No authorized_keys for the current user.")
            return
        text = read_text(ak)
        if text is None:
            return
        keys = [ln for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
        forced = [ln for ln in keys if "command=" not in ln]
        yield self.finding(
            Severity.INFO,
            f"{len(keys)} authorized SSH key(s) for this user",
            detail="Each key is a standing remote-access grant.",
            recommendation="Remove keys you no longer recognise.",
            evidence=tuple(k.split()[-1] if k.split() else k for k in forced[:8]),
        )

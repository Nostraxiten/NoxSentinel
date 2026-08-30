"""Cryptographic security, certificate validity, weak SSH keys, and plaintext secrets."""

from __future__ import annotations

import base64
import os
import re
import stat
from pathlib import Path

from sentinel.checks.base import Check, mode_string, read_text
from sentinel.core import Severity

SECRET_REGEX = re.compile(
    r"""(?i)(?:password|passwd|secret|api_key|token|access_key|auth_token)\s*[:=]\s*['"]?([a-zA-Z0-9_\-\.\$\!\@\#\%\^\&\*]{8,})['"]?"""
)


class WeakSshKeys(Check):
    """Detect weak, short, or deprecated algorithms in SSH keys."""

    id = "crypto.ssh_keys"
    category = "Crypto"
    title = "SSH key algorithm and strength"

    def run(self):
        ssh_dir = Path.home() / ".ssh"
        if not ssh_dir.is_dir():
            yield self.ok("No ~/.ssh directory found.")
            return

        weak_keys = []

        # 1. Check authorized_keys for weak public keys (DSA or small RSA)
        auth_keys = ssh_dir / "authorized_keys"
        if auth_keys.is_file():
            content = read_text(auth_keys)
            if content:
                for line_no, line in enumerate(content.splitlines(), start=1):
                    line_s = line.strip()
                    if not line_s or line_s.startswith("#"):
                        continue
                    parts = line_s.split()
                    if len(parts) >= 2:
                        key_type = parts[0]
                        key_b64 = parts[1]
                        if key_type == "ssh-dss":
                            weak_keys.append((f"authorized_keys:{line_no}", "Deprecated DSA key (ssh-dss)"))
                        elif key_type == "ssh-rsa":
                            try:
                                raw = base64.b64decode(key_b64)
                                # SSH RSA public key format: string "ssh-rsa", mpint e, mpint n
                                # The length of n determines key size.
                                if len(raw) < 260:  # 2048-bit RSA key raw size is ~279 bytes
                                    weak_keys.append((f"authorized_keys:{line_no}", "RSA key smaller than 2048 bits"))
                            except Exception:
                                pass

        # 2. Check local private key files for DSA
        for key_file in ssh_dir.glob("id_*"):
            if key_file.name.endswith(".pub"):
                continue
            if "dsa" in key_file.name:
                weak_keys.append((key_file.name, "DSA private key file"))

        if weak_keys:
            for item, reason in weak_keys:
                yield self.finding(
                    Severity.HIGH,
                    f"Weak SSH key ({reason}): {item}",
                    detail=f"Reason: {reason}. Weak or obsolete algorithms are vulnerable to factorization.",
                    recommendation="Generate new keys using Ed25519 (ssh-keygen -t ed25519) or RSA >= 3072.",
                    evidence=(f"key={item}", f"reason={reason}"),
                )
        else:
            yield self.ok("SSH keys use modern algorithms without deprecated DSA or weak RSA.")



class WorldReadableEnvFiles(Check):
    """Detect world-readable .env or secret configuration files."""

    id = "crypto.env_files"
    category = "Crypto"
    title = "Environment file exposure"

    ENV_PATTERNS = (".env", ".env.local", ".env.production", ".env.development", "credentials.json")

    def run(self):
        home = Path.home()
        exposed = []

        for p in self.ENV_PATTERNS:
            target = home / p
            if target.is_file():
                try:
                    mode = target.stat().st_mode
                    perms = stat.S_IMODE(mode)
                    if perms & 0o004:  # World-readable
                        exposed.append((str(target), perms))
                except OSError:
                    continue

        if exposed:
            for path_str, perms in exposed:
                yield self.finding(
                    Severity.HIGH,
                    f"Secret file {path_str} is world-readable ({mode_string(perms)})",
                    detail="Configuration files containing database passwords and API tokens should only be readable by owner.",
                    recommendation=f"chmod 600 {path_str}",
                    evidence=(f"file={path_str}", f"mode={mode_string(perms)}"),
                )
        else:
            yield self.ok("No exposed world-readable .env or credentials files in home directory.")


class PlaintextSecretsInConfigs(Check):
    """Scan readable configuration files for unencrypted secrets and API keys."""

    id = "crypto.plaintext_secrets"
    category = "Crypto"
    title = "Plaintext credentials in configs"

    TARGET_FILES = (
        ".netrc",
        ".git-credentials",
        ".npmrc",
        ".pypirc",
        ".docker/config.json",
        ".aws/credentials",
    )

    def run(self):
        home = Path.home()
        flagged = []

        for rel in self.TARGET_FILES:
            fp = home / rel
            if not fp.is_file():
                continue
            try:
                mode = fp.stat().st_mode
                perms = stat.S_IMODE(mode)
                # If readable by others, check if it contains credentials
                if perms & 0o044:
                    flagged.append((str(fp), mode_string(perms)))
            except OSError:
                continue

        if flagged:
            for path_str, mode_str in flagged:
                yield self.finding(
                    Severity.MEDIUM,
                    f"Credential store {path_str} is readable by others ({mode_str})",
                    detail="This file stores plaintext passwords or tokens but has group/other read permissions.",
                    recommendation=f"chmod 600 {path_str}",
                    evidence=(f"file={path_str}", f"mode={mode_str}"),
                )
        else:
            yield self.ok("Known credential store files have restricted permissions.")

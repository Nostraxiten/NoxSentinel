"""Account and privilege checks derived from /etc/passwd and /etc/shadow."""

from __future__ import annotations

from sentinel.checks.base import Check, read_text
from sentinel.core import Severity


def _passwd_rows():
    data = read_text("/etc/passwd")
    if not data:
        return
    for line in data.splitlines():
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 7:
            yield parts


class RootEquivalentAccounts(Check):
    id = "acct.uid0"
    category = "Accounts"
    title = "UID 0 accounts"
    posix_only = True

    def run(self):
        root_accounts = [p[0] for p in _passwd_rows() if p[2] == "0"]
        extra = [name for name in root_accounts if name != "root"]
        if extra:
            yield self.finding(
                Severity.CRITICAL,
                f"{len(extra)} non-root account(s) with UID 0",
                detail="Any UID 0 account has full root privileges.",
                recommendation="Give these accounts a unique UID or remove them.",
                evidence=tuple(extra),
            )
        elif root_accounts:
            yield self.ok("Only 'root' holds UID 0.")


class EmptyPasswordAccounts(Check):
    id = "acct.empty_pw"
    category = "Accounts"
    title = "Accounts without a password"
    posix_only = True

    def run(self):
        data = read_text("/etc/shadow")
        if data is None:
            yield self.finding(
                Severity.INFO,
                "Cannot read /etc/shadow",
                detail="Run as root for password-state checks.",
            )
            return
        empty = []
        for line in data.splitlines():
            parts = line.split(":")
            if len(parts) >= 2 and parts[1] == "":
                empty.append(parts[0])
        if empty:
            yield self.finding(
                Severity.CRITICAL,
                f"{len(empty)} account(s) with an empty password",
                recommendation="Lock these accounts: passwd -l <user>",
                evidence=tuple(empty),
            )
        else:
            yield self.ok("No accounts with empty passwords.")


class LoginShellAudit(Check):
    id = "acct.login_shells"
    category = "Accounts"
    title = "System accounts with login shells"
    posix_only = True

    NON_INTERACTIVE = {"/usr/sbin/nologin", "/sbin/nologin", "/bin/false",
                       "/usr/bin/false", ""}

    def run(self):
        risky = []
        for parts in _passwd_rows():
            name, _pw, uid, _gid, _info, _home, shell = parts[:7]
            try:
                uid_n = int(uid)
            except ValueError:
                continue
            # System accounts (below 1000, excluding root) shouldn't log in.
            if 0 < uid_n < 1000 and shell not in self.NON_INTERACTIVE:
                risky.append(f"{name} -> {shell}")
        if risky:
            yield self.finding(
                Severity.LOW,
                f"{len(risky)} system account(s) with an interactive shell",
                detail="Service accounts with real shells widen the attack surface.",
                recommendation="Set their shell to /usr/sbin/nologin.",
                evidence=tuple(risky[:10]),
            )
        else:
            yield self.ok("System accounts use non-interactive shells.")

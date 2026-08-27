"""Check registry: the ordered list of every audit Nox Sentinel runs."""

from __future__ import annotations

from sentinel.checks import accounts, cron, filesystem, kernel, network, ssh
from sentinel.checks.base import Check

#: Every check class, grouped by module for a stable, readable order.
ALL_CHECKS: tuple[type[Check], ...] = (
    filesystem.SensitiveFilePermissions,
    filesystem.HomeDirExposure,
    filesystem.SshKeyPermissions,
    filesystem.WorldWritableSearch,
    filesystem.SuidBinaryInventory,
    accounts.RootEquivalentAccounts,
    accounts.EmptyPasswordAccounts,
    accounts.LoginShellAudit,
    ssh.SshdHardening,
    ssh.AuthorizedKeysReview,
    network.ListeningServices,
    kernel.SysctlHardening,
    kernel.DangerousPathEntries,
    kernel.UmaskCheck,
    cron.WritableCronJobs,
)


def build_checks(categories: set[str] | None = None) -> list[Check]:
    """Instantiate applicable checks, optionally filtered by category."""
    checks = []
    for cls in ALL_CHECKS:
        instance = cls()
        if not instance.applicable():
            continue
        if categories and instance.category.lower() not in categories:
            continue
        checks.append(instance)
    return checks


def known_categories() -> list[str]:
    seen: list[str] = []
    for cls in ALL_CHECKS:
        if cls.category not in seen:
            seen.append(cls.category)
    return seen

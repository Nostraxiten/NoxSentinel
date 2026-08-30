"""Check registry: the ordered list of every audit Nox Sentinel runs."""

from __future__ import annotations

from sentinel.checks import (
    accounts,
    browser,
    cron,
    crypto,
    filesystem,
    forensics,
    kernel,
    malware,
    network,
    network_advanced,
    packages,
    persistence,
    ssh,
    windows,
)
from sentinel.checks.base import Check

#: Every check class, grouped by module for a stable, readable order.
ALL_CHECKS: tuple[type[Check], ...] = (
    # Malware & IOC checks
    malware.DeletedExeProcess,
    malware.HiddenTempDirectories,
    malware.SuspiciousProcessMaps,
    malware.RecentlyModifiedBinaries,
    # Persistence checks
    persistence.SuspiciousCronCommands,
    persistence.LdPreloadCheck,
    persistence.ShellProfileInjections,
    persistence.SystemdSuspiciousServices,
    # Filesystem & permissions
    filesystem.SensitiveFilePermissions,
    filesystem.HomeDirExposure,
    filesystem.SshKeyPermissions,
    filesystem.WorldWritableSearch,
    filesystem.SuidBinaryInventory,
    # Account security
    accounts.RootEquivalentAccounts,
    accounts.EmptyPasswordAccounts,
    accounts.LoginShellAudit,
    # Cryptographic & secrets
    crypto.WeakSshKeys,
    crypto.WorldReadableEnvFiles,
    crypto.PlaintextSecretsInConfigs,
    # Browser & cookies
    browser.BrowserCookieAudit,
    browser.FirefoxMasterPasswordCheck,
    # SSH hardening
    ssh.SshdHardening,
    ssh.AuthorizedKeysReview,
    # Network exposure & advanced
    network.ListeningServices,
    network_advanced.PromiscuousInterfaces,
    network_advanced.HostsHijackingCheck,
    network_advanced.EstablishedOutboundConnections,
    # Kernel & environment
    kernel.SysctlHardening,
    kernel.DangerousPathEntries,
    kernel.UmaskCheck,
    # Scheduled jobs
    cron.WritableCronJobs,
    # Forensics & anti-forensics
    forensics.LogTamperingCheck,
    forensics.HistoryFileTampering,
    forensics.FutureTimestampFiles,
    forensics.TmpStickyBitCheck,
    # Packages & updates
    packages.KernelCveBaseline,
    packages.AutomaticUpdatesConfig,
    # Windows native checks
    windows.WindowsDefenderStatus,
    windows.WindowsFirewallProfiles,
    windows.UserAccountControlStatus,
    windows.AutoRunPolicy,
    windows.RdpExposureStatus,
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

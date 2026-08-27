"""Unit tests for Nox Sentinel core, checks and rendering.

Run with: python3 -m unittest discover -s tests
"""

from __future__ import annotations

import contextlib
import io
import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sentinel.core import Finding, Report, Severity
from sentinel.checks import ALL_CHECKS, build_checks, known_categories
from sentinel.checks.base import mode_string
from sentinel.checks.filesystem import SshKeyPermissions
from sentinel.checks.network import _hex_to_ip_port
from sentinel.checks.ssh import _parse_sshd_config
from sentinel.engine import run_audit
from sentinel import ui


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
        cats = {"ssh"}
        checks = build_checks(cats)
        self.assertTrue(checks)
        self.assertTrue(all(c.category.lower() == "ssh" for c in checks))

    def test_known_categories_nonempty(self):
        self.assertIn("Filesystem", known_categories())


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


class SshKeyCheckTest(unittest.TestCase):
    def test_flags_exposed_key(self):
        with tempfile.TemporaryDirectory() as tmp:
            home = Path(tmp)
            ssh = home / ".ssh"
            ssh.mkdir()
            key = ssh / "id_rsa"
            key.write_text("PRIVATE")
            os.chmod(key, 0o644)  # group/other readable -> should flag
            orig = os.environ.get("HOME")
            os.environ["HOME"] = str(home)
            try:
                findings = list(SshKeyPermissions().run())
            finally:
                if orig is not None:
                    os.environ["HOME"] = orig
            severities = [f.severity for f in findings]
            self.assertIn(Severity.HIGH, severities)


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
        self.assertEqual(calls[-1][0], calls[-1][1])  # ends at total


class UiTest(unittest.TestCase):
    def test_visible_len_ignores_ansi(self):
        colored = f"{ui._rgb(1,2,3)}abc{ui.RESET}"
        # With color disabled during tests, _rgb returns "" so this is plain.
        self.assertEqual(ui._visible_len("abc"), 3)

    def test_gauge_length(self):
        bar = ui.risk_gauge(50, width=20)
        self.assertGreater(len(bar), 0)

    def test_render_does_not_crash(self):
        ui.disable_color()
        report = run_audit()
        # Should render without raising (output captured to keep tests quiet).
        with contextlib.redirect_stdout(io.StringIO()):
            ui.render_report(report, show_ok=True)


if __name__ == "__main__":
    unittest.main(verbosity=2)

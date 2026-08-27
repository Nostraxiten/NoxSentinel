"""Audit engine: run checks, collect findings, build a scored report."""

from __future__ import annotations

import time
from typing import Callable, Iterable

from sentinel.checks import build_checks
from sentinel.checks.base import Check
from sentinel.core import Finding, Report, Severity

ProgressHook = Callable[[int, int, Check], None]


def run_audit(categories: set[str] | None = None,
              progress: ProgressHook | None = None) -> Report:
    """Execute the selected checks and return an aggregated Report.

    ``progress`` is called before each check with (index, total, check) so a
    UI can render a live progress bar.
    """
    report = Report()
    checks = build_checks(categories)
    total = len(checks)
    for index, check in enumerate(checks, start=1):
        if progress:
            progress(index, total, check)
        for finding in _safe_run(check):
            report.add(finding)
    report.finished_at = time.time()
    return report


def _safe_run(check: Check) -> Iterable[Finding]:
    """Run a check, converting any crash into a low-noise INFO finding."""
    try:
        yield from check.run()
    except Exception as exc:  # a broken check must not abort the audit
        yield Finding(
            check.id, check.category, f"{check.title} (check error)",
            Severity.INFO, detail=f"{type(exc).__name__}: {exc}",
        )

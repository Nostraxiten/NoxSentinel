"""Scheduled-task checks: writable cron entries and scripts."""

from __future__ import annotations

import os
import stat
from pathlib import Path

from sentinel.checks.base import Check
from sentinel.core import Severity

CRON_DIRS = (
    "/etc/cron.d", "/etc/cron.hourly", "/etc/cron.daily",
    "/etc/cron.weekly", "/etc/cron.monthly",
)


class WritableCronJobs(Check):
    id = "cron.writable"
    category = "Scheduled tasks"
    title = "Writable cron entries"
    posix_only = True

    def run(self):
        offenders = []
        checked = False
        for d in CRON_DIRS:
            base = Path(d)
            if not base.is_dir():
                continue
            checked = True
            for item in base.iterdir():
                try:
                    perms = stat.S_IMODE(item.stat().st_mode)
                except OSError:
                    continue
                if perms & 0o022:
                    offenders.append(f"{item} ({perms:04o})")
        crontab = Path("/etc/crontab")
        if crontab.exists():
            checked = True
            try:
                perms = stat.S_IMODE(crontab.stat().st_mode)
                if perms & 0o022:
                    offenders.append(f"{crontab} ({perms:04o})")
            except OSError:
                pass
        if offenders:
            yield self.finding(
                Severity.HIGH,
                f"{len(offenders)} group/world-writable cron entry(ies)",
                detail="Writable cron jobs let other users run code as their owner.",
                recommendation="chmod go-w on these files (root cron should be 0644 or tighter).",
                evidence=tuple(offenders[:10]),
            )
        elif checked:
            yield self.ok("Cron entries are not writable by others.")
        else:
            yield self.ok("No cron directories present.")

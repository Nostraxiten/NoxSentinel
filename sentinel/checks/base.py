"""Base class and shared helpers for security checks."""

from __future__ import annotations

import os
from pathlib import Path

from sentinel.core import Finding, Severity


class Check:
    """A passive, read-only security check.

    Subclasses set ``id``, ``category`` and ``title`` and implement ``run``,
    yielding :class:`Finding` objects. A check that finds nothing wrong may
    yield a single ``Severity.OK`` finding to signal it ran cleanly.
    """

    id: str = "base"
    category: str = "general"
    title: str = "Unnamed check"
    #: Checks tagged posix_only are skipped on Windows.
    posix_only: bool = False

    def applicable(self) -> bool:
        if self.posix_only and os.name != "posix":
            return False
        return True

    def run(self):  # pragma: no cover - interface only
        raise NotImplementedError

    # -- finding helpers -------------------------------------------------
    def ok(self, detail: str = "", evidence=()) -> Finding:
        return Finding(self.id, self.category, self.title, Severity.OK, detail, evidence=tuple(evidence))

    def finding(self, severity: Severity, title: str, detail: str = "",
                recommendation: str = "", evidence=()) -> Finding:
        return Finding(self.id, self.category, title, severity, detail,
                       recommendation, tuple(evidence))


def read_text(path: str | os.PathLike) -> str | None:
    """Best-effort read of a text file; returns None if unreadable."""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return None


def mode_string(mode: int) -> str:
    """Render a permission mode as an octal string, e.g. 0644."""
    return f"{mode & 0o7777:04o}"

"""Base class and shared helpers for security checks."""

from __future__ import annotations

import os
from pathlib import Path
from typing import Any

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
    #: Checks tagged posix_only are skipped on Windows/non-POSIX systems.
    posix_only: bool = False
    #: Checks tagged windows_only are skipped on Linux/POSIX systems.
    windows_only: bool = False

    def applicable(self) -> bool:
        if self.posix_only and os.name != "posix":
            return False
        if self.windows_only and os.name != "nt":
            return False
        return True

    def run(self):  # pragma: no cover - interface only
        raise NotImplementedError

    # -- finding helpers -------------------------------------------------
    def ok(self, detail: str = "", evidence: Any = ()) -> Finding:
        return Finding(self.id, self.category, self.title, Severity.OK, detail, evidence=tuple(evidence))

    def finding(self, severity: Severity, title: str, detail: str = "",
                recommendation: str = "", evidence: Any = ()) -> Finding:
        return Finding(self.id, self.category, title, severity, detail,
                       recommendation, tuple(evidence))


def is_posix() -> bool:
    return os.name == "posix"


def is_windows() -> bool:
    return os.name == "nt"


def is_termux() -> bool:
    return "TERMUX_VERSION" in os.environ or Path("/data/data/com.termux").exists()


def read_text(path: str | os.PathLike) -> str | None:
    """Best-effort read of a text file; returns None if unreadable."""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")
    except (OSError, ValueError):
        return None


def read_bytes(path: str | os.PathLike, max_bytes: int = 1048576) -> bytes | None:
    """Best-effort read of binary file up to max_bytes."""
    try:
        with open(path, "rb") as f:
            return f.read(max_bytes)
    except (OSError, ValueError):
        return None


def mode_string(mode: int) -> str:
    """Render a permission mode as an octal string, e.g. 0644."""
    return f"{mode & 0o7777:04o}"


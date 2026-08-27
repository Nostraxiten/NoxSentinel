"""Core data model for Nox Sentinel: severities, findings and scored reports."""

from __future__ import annotations

import enum
import platform
import socket
import time
from dataclasses import dataclass, field


class Severity(enum.IntEnum):
    """Ordered severity levels. Higher value == more urgent."""

    OK = 0
    INFO = 1
    LOW = 2
    MEDIUM = 3
    HIGH = 4
    CRITICAL = 5

    @property
    def label(self) -> str:
        return self.name

    @property
    def weight(self) -> int:
        """Risk points a single finding of this severity contributes."""
        return {
            Severity.OK: 0,
            Severity.INFO: 0,
            Severity.LOW: 2,
            Severity.MEDIUM: 6,
            Severity.HIGH: 15,
            Severity.CRITICAL: 30,
        }[self]


@dataclass(frozen=True)
class Finding:
    """A single observation produced by a check."""

    check_id: str
    category: str
    title: str
    severity: Severity
    detail: str = ""
    recommendation: str = ""
    evidence: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict:
        return {
            "check_id": self.check_id,
            "category": self.category,
            "title": self.title,
            "severity": self.severity.label,
            "detail": self.detail,
            "recommendation": self.recommendation,
            "evidence": list(self.evidence),
        }


@dataclass
class Report:
    """Aggregated result of a full audit run."""

    findings: list[Finding] = field(default_factory=list)
    started_at: float = field(default_factory=time.time)
    finished_at: float = 0.0
    host: str = field(default_factory=socket.gethostname)
    system: str = field(default_factory=lambda: f"{platform.system()} {platform.release()}")

    def add(self, finding: Finding) -> None:
        self.findings.append(finding)

    @property
    def actionable(self) -> list[Finding]:
        """Findings worth a human's attention, worst first."""
        items = [f for f in self.findings if f.severity >= Severity.LOW]
        return sorted(items, key=lambda f: f.severity, reverse=True)

    def count(self, severity: Severity) -> int:
        return sum(1 for f in self.findings if f.severity == severity)

    @property
    def risk_score(self) -> int:
        """Total accumulated risk points, capped at 100."""
        return min(100, sum(f.severity.weight for f in self.findings))

    @property
    def grade(self) -> str:
        score = self.risk_score
        if score == 0:
            return "A+"
        if score <= 8:
            return "A"
        if score <= 20:
            return "B"
        if score <= 40:
            return "C"
        if score <= 65:
            return "D"
        return "F"

    @property
    def duration(self) -> float:
        end = self.finished_at or time.time()
        return end - self.started_at

    def to_dict(self) -> dict:
        return {
            "host": self.host,
            "system": self.system,
            "risk_score": self.risk_score,
            "grade": self.grade,
            "duration_seconds": round(self.duration, 3),
            "totals": {
                sev.label: self.count(sev)
                for sev in Severity
                if sev not in (Severity.OK, Severity.INFO)
            },
            "findings": [f.to_dict() for f in self.findings],
        }

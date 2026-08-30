"""Terminal presentation layer: colors, banner, and the report dashboard.

The rendering is deliberately dependency-free. Colors are ANSI escapes that
auto-disable when output is not a TTY, when NO_COLOR is set, or when the
terminal declares itself dumb.
"""

from __future__ import annotations

import os
import shutil
import sys

from sentinel import __version__
from sentinel.core import Report, Severity

# --- color handling -----------------------------------------------------

def _color_enabled() -> bool:
    if os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("TERM") == "dumb":
        return False
    return sys.stdout.isatty()


_ENABLED = _color_enabled()


def disable_color() -> None:
    global _ENABLED
    _ENABLED = False


def _c(code: str) -> str:
    return code if _ENABLED else ""


RESET = _c("\033[0m")
BOLD = _c("\033[1m")
DIM = _c("\033[2m")
ITALIC = _c("\033[3m")


def _rgb(r: int, g: int, b: int) -> str:
    return _c(f"\033[38;2;{r};{g};{b}m")


# Nocturnal palette – cool indigo/violet with warm alert accents.
INK = _rgb(122, 132, 255)      # primary accent (indigo)
VIOLET = _rgb(178, 128, 255)
MIST = _rgb(150, 160, 190)     # muted text
FROST = _rgb(120, 220, 232)    # cyan detail

SEVERITY_STYLE = {
    Severity.OK: (_rgb(80, 200, 140), "OK  "),
    Severity.INFO: (_rgb(120, 170, 220), "INFO"),
    Severity.LOW: (_rgb(120, 200, 120), "LOW "),
    Severity.MEDIUM: (_rgb(240, 200, 90), "MED "),
    Severity.HIGH: (_rgb(255, 140, 70), "HIGH"),
    Severity.CRITICAL: (_rgb(255, 90, 95), "CRIT"),
}

GRADE_COLOR = {
    "A+": _rgb(80, 220, 150), "A": _rgb(120, 210, 130),
    "B": _rgb(200, 210, 100), "C": _rgb(240, 200, 90),
    "D": _rgb(255, 140, 70), "F": _rgb(255, 90, 95),
}


def _width(minimum: int = 64, maximum: int = 96) -> int:
    cols = shutil.get_terminal_size((80, 24)).columns
    return max(minimum, min(maximum, cols))


def _visible_len(text: str) -> int:
    """Length of a string ignoring ANSI escape sequences."""
    out, i = 0, 0
    while i < len(text):
        if text[i] == "\033":
            while i < len(text) and text[i] != "m":
                i += 1
            i += 1
            continue
        out += 1
        i += 1
    return out


# --- primitives ---------------------------------------------------------

def rule(width: int, char: str = "─", color: str = MIST) -> str:
    return f"{color}{char * width}{RESET}"


def panel_top(title: str, width: int, color: str = INK) -> str:
    label = f" {title} "
    # prefix "╭─" (2) + label + fill + "╮" (1) must total `width`.
    fill = max(0, width - 3 - _visible_len(label))
    return f"{color}╭─{RESET}{BOLD}{color}{label}{RESET}{color}{'─' * fill}╮{RESET}"


def panel_bottom(width: int, color: str = INK) -> str:
    return f"{color}╰{'─' * (width - 2)}╯{RESET}"


def panel_line(content: str, width: int, color: str = INK) -> str:
    pad = width - _visible_len(content) - 3
    pad = max(0, pad)
    return f"{color}│{RESET} {content}{' ' * pad}{color}│{RESET}"


# --- banner -------------------------------------------------------------

BANNER = r"""
 ▄▄▄   ▄▄                        ▄▄▄▄                                     ██                         ▄▄▄▄
 ███   ██                      ▄█▀▀▀▀█                         ██         ▀▀                         ▀▀██
 ██▀█  ██   ▄████▄   ▀██  ██▀  ██▄        ▄████▄   ██▄████▄  ███████    ████     ██▄████▄   ▄████▄     ██
 ██ ██ ██  ██▀  ▀██    ████     ▀████▄   ██▄▄▄▄██  ██▀   ██    ██         ██     ██▀   ██  ██▄▄▄▄██    ██
 ██  █▄██  ██    ██    ▄██▄         ▀██  ██▀▀▀▀▀▀  ██    ██    ██         ██     ██    ██  ██▀▀▀▀▀▀    ██
 ██   ███  ▀██▄▄██▀   ▄█▀▀█▄   █▄▄▄▄▄█▀  ▀██▄▄▄▄█  ██    ██    ██▄▄▄   ▄▄▄██▄▄▄  ██    ██  ▀██▄▄▄▄█    ██▄▄▄
 ▀▀   ▀▀▀    ▀▀▀▀    ▀▀▀  ▀▀▀   ▀▀▀▀▀      ▀▀▀▀▀   ▀▀    ▀▀     ▀▀▀▀   ▀▀▀▀▀▀▀▀  ▀▀    ▀▀    ▀▀▀▀▀      ▀▀▀▀"""


def print_banner() -> None:
    width = _width()
    for line in BANNER.strip("\n").splitlines():
        print(f"{INK}{line}{RESET}")
    tag = f"{VIOLET}Nox Sentinel{RESET} {DIM}v{__version__}{RESET} {MIST}· local security posture auditor{RESET}"
    print(f"   {tag}")
    print(f"   {rule(width - 3)}")


# --- gauge --------------------------------------------------------------

def risk_gauge(score: int, width: int = 32) -> str:
    filled = round(score / 100 * width)
    # Green -> amber -> red across the bar.
    bar = ""
    for i in range(width):
        if i < filled:
            ratio = i / max(1, width - 1)
            if ratio < 0.4:
                col = _rgb(80, 200, 140)
            elif ratio < 0.7:
                col = _rgb(240, 200, 90)
            else:
                col = _rgb(255, 90, 95)
            bar += f"{col}█{RESET}"
        else:
            bar += f"{DIM}·{RESET}"
    return bar


# --- report rendering ---------------------------------------------------

def render_report(report: Report, show_ok: bool = False) -> None:
    width = _width()
    print()
    _render_summary(report, width)
    _render_priority_actions(report, width)
    _render_findings(report, width, show_ok)
    _render_footer(report, width)


def _render_priority_actions(report: Report, width: int) -> None:
    """Render top priority actions for highest severity findings."""
    urgent = [f for f in report.actionable if f.severity >= Severity.MEDIUM and f.recommendation]
    if not urgent:
        return

    top = urgent[:4]
    print(panel_top("TOP REMEDIATION PRIORITIES", width, color=VIOLET))
    for i, f in enumerate(top, start=1):
        col, label = SEVERITY_STYLE[f.severity]
        title_trunc = f.title if len(f.title) <= 46 else f.title[:43] + "..."
        print(panel_line(f"{BOLD}{col}[{label}]{RESET} {BOLD}{i}. {title_trunc}{RESET}", width, color=VIOLET))
        rec_trunc = f.recommendation if len(f.recommendation) <= 56 else f.recommendation[:53] + "..."
        print(panel_line(f"   {INK}➜ {rec_trunc}{RESET}", width, color=VIOLET))
        if i < len(top):
            print(panel_line("", width, color=VIOLET))
    print(panel_bottom(width, color=VIOLET))
    print()



def _render_summary(report: Report, width: int) -> None:
    grade_col = GRADE_COLOR.get(report.grade, MIST)
    print(panel_top("AUDIT SUMMARY", width))
    print(panel_line(f"{MIST}host{RESET}    {report.host}", width))
    print(panel_line(f"{MIST}system{RESET}  {report.system}", width))
    print(panel_line(f"{MIST}checks{RESET}  {len(report.findings)} findings in "
                     f"{report.duration:.2f}s", width))
    print(panel_line("", width))

    gauge = risk_gauge(report.risk_score)
    grade = f"{BOLD}{grade_col}{report.grade}{RESET}"
    print(panel_line(f"{BOLD}risk{RESET}    {gauge} {report.risk_score:>3}/100   "
                     f"grade {grade}", width))

    counts = []
    for sev in (Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW):
        n = report.count(sev)
        col, _label = SEVERITY_STYLE[sev]
        style = col if n else DIM
        counts.append(f"{style}{n} {sev.label.lower()}{RESET}")
    print(panel_line("        " + "  ".join(counts), width))
    print(panel_bottom(width))
    print()


def _badge(sev: Severity) -> str:
    col, label = SEVERITY_STYLE[sev]
    return f"{col}▐{BOLD}{label}{RESET}{col}▌{RESET}"


def _render_findings(report: Report, width: int, show_ok: bool) -> None:
    items = report.findings if show_ok else report.actionable
    if not items:
        print(f"   {SEVERITY_STYLE[Severity.OK][0]}✔ No actionable findings. "
              f"This host passes every check.{RESET}\n")
        return

    current_cat = None
    ordered = sorted(items, key=lambda f: (f.category, -f.severity))
    for f in ordered:
        if f.category != current_cat:
            current_cat = f.category
            print(f"   {BOLD}{FROST}{f.category.upper()}{RESET}")
            print(f"   {rule(width - 3, '·')}")
        print(f"   {_badge(f.severity)}  {BOLD}{f.title}{RESET}")
        if f.detail:
            print(f"        {MIST}{f.detail}{RESET}")
        for ev in f.evidence:
            print(f"        {DIM}· {ev}{RESET}")
        if f.recommendation:
            print(f"        {INK}➜ {f.recommendation}{RESET}")
        print()


def _render_footer(report: Report, width: int) -> None:
    print(f"   {rule(width - 3)}")
    top = report.actionable[:1]
    if top and top[0].severity >= Severity.HIGH:
        msg = f"{SEVERITY_STYLE[Severity.HIGH][0]}Priority: address the {top[0].severity.label} finding first.{RESET}"
    elif report.actionable:
        msg = f"{MIST}Review the findings above and re-run to confirm fixes.{RESET}"
    else:
        msg = f"{SEVERITY_STYLE[Severity.OK][0]}Clean bill of health.{RESET}"
    print(f"   {msg}")
    print(f"   {DIM}Nox Sentinel · passive & read-only · nothing was modified.{RESET}\n")

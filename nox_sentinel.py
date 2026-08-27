#!/usr/bin/env python3
"""Nox Sentinel - local security posture auditor.

Entry point and command-line interface. Runs a battery of passive, read-only
host-hardening checks, scores the resulting risk, and prints a colored
dashboard (or JSON for pipelines).

Usage:
    python3 nox_sentinel.py                 # full audit, dashboard output
    python3 nox_sentinel.py --json          # machine-readable report
    python3 nox_sentinel.py -c ssh -c network   # only selected categories
    python3 nox_sentinel.py --list-checks   # show what would run
"""

from __future__ import annotations

import argparse
import json
import sys
import time
from pathlib import Path

# Make the package importable when run as a loose script.
sys.path.insert(0, str(Path(__file__).resolve().parent))

from sentinel import __version__
from sentinel.checks import build_checks, known_categories
from sentinel.core import Report, Severity
from sentinel.engine import run_audit
from sentinel import ui


def _progress(index: int, total: int, check) -> None:
    if not ui._ENABLED:
        return
    width = 24
    filled = round(index / total * width)
    bar = ui.INK + "█" * filled + ui.DIM + "·" * (width - filled) + ui.RESET
    line = (f"\r   {ui.MIST}scanning{ui.RESET} {bar} "
            f"{index:>2}/{total}  {ui.DIM}{check.title[:32]:<32}{ui.RESET}")
    sys.stdout.write(line)
    sys.stdout.flush()
    if index == total:
        sys.stdout.write("\r" + " " * (width + 60) + "\r")
        sys.stdout.flush()


def _build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="nox-sentinel",
        description="Passive local security posture auditor.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-c", "--category", action="append", metavar="NAME",
                   help="only run checks in this category (repeatable)")
    p.add_argument("--json", action="store_true",
                   help="emit the report as JSON instead of a dashboard")
    p.add_argument("-o", "--output", metavar="FILE",
                   help="write the report (JSON) to a file as well")
    p.add_argument("--show-ok", action="store_true",
                   help="include passing checks in the dashboard")
    p.add_argument("--no-color", action="store_true", help="disable ANSI colors")
    p.add_argument("--list-checks", action="store_true",
                   help="list the checks that would run and exit")
    p.add_argument("--list-categories", action="store_true",
                   help="list available categories and exit")
    p.add_argument("--fail-on", metavar="SEV", default=None,
                   choices=[s.label.lower() for s in Severity if s >= Severity.LOW],
                   help="exit non-zero if any finding reaches this severity "
                        "(low|medium|high|critical)")
    p.add_argument("--version", action="version",
                   version=f"Nox Sentinel {__version__}")
    return p


def _normalize_categories(raw):
    if not raw:
        return None
    valid = {c.lower(): c for c in known_categories()}
    chosen = set()
    for name in raw:
        key = name.lower()
        if key not in valid:
            sys.stderr.write(
                f"Unknown category '{name}'. Known: "
                f"{', '.join(known_categories())}\n")
            raise SystemExit(2)
        chosen.add(key)
    return chosen


def _list_checks(categories) -> int:
    ui.print_banner()
    print()
    current = None
    for check in build_checks(categories):
        if check.category != current:
            current = check.category
            print(f"   {ui.BOLD}{ui.FROST}{check.category}{ui.RESET}")
        print(f"     {ui.MIST}{check.id:<22}{ui.RESET} {check.title}")
    print()
    return 0


def _exit_code(report: Report, fail_on: str | None) -> int:
    if not fail_on:
        return 0
    threshold = Severity[fail_on.upper()]
    worst = max((f.severity for f in report.findings), default=Severity.OK)
    return 1 if worst >= threshold else 0


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)
    if args.no_color:
        ui.disable_color()

    categories = _normalize_categories(args.category)

    if args.list_categories:
        for name in known_categories():
            print(name)
        return 0
    if args.list_checks:
        return _list_checks(categories)

    if not args.json:
        ui.print_banner()

    report = run_audit(categories, progress=None if args.json else _progress)

    if args.output:
        Path(args.output).write_text(json.dumps(report.to_dict(), indent=2))

    if args.json:
        print(json.dumps(report.to_dict(), indent=2))
    else:
        ui.render_report(report, show_ok=args.show_ok)
        if args.output:
            print(f"   {ui.DIM}JSON report written to {args.output}{ui.RESET}\n")

    return _exit_code(report, args.fail_on)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        sys.stderr.write("\nInterrupted.\n")
        raise SystemExit(130)

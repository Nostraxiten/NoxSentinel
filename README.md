# Nox Sentinel
<img width="429" height="452" alt="Captura de pantalla 2026-08-27 164452" src="https://github.com/user-attachments/assets/2acf7a65-35fc-48ba-a76e-96cee3df7637" />

**A local security posture auditor.** Nox Sentinel inspects the machine it
runs on for hardening weaknesses — insecure file permissions, exposed
services, weak SSH configuration, risky accounts, unsafe kernel flags — then
scores the overall risk and renders a clean terminal dashboard.

It is **passive and read-only**: every check merely observes the system. Nox
Sentinel never changes a file, never touches the network, and never runs an
external command. It depends only on the Python standard library.

## Why

Most "security tools" are a loose bag of wrappers. Nox Sentinel is one
focused thing done well: a hardening baseline you can run on any Linux box in
under a second, with a report that tells you *what* is wrong, *why* it
matters, and the *exact command* to fix it.

## Quick start

No install, no dependencies:

```bash
python3 nox_sentinel.py
```

That runs the full audit and prints the dashboard. Some checks (e.g. reading
`/etc/shadow`) reveal more when run as root, but the tool works fine as an
unprivileged user and simply notes what it could not inspect.

## Usage

```bash
python3 nox_sentinel.py                      # full audit, colored dashboard
python3 nox_sentinel.py --show-ok            # also show checks that passed
python3 nox_sentinel.py -c ssh -c network    # only selected categories
python3 nox_sentinel.py --json               # machine-readable report
python3 nox_sentinel.py -o report.json       # also save JSON to a file
python3 nox_sentinel.py --fail-on high       # exit non-zero for CI gating
python3 nox_sentinel.py --list-checks        # show what would run
python3 nox_sentinel.py --no-color           # plain text
```

### CI gating

`--fail-on` makes Nox Sentinel a build gate. It exits `1` when any finding
reaches the given severity, so a pipeline can block a host that regresses:

```bash
python3 nox_sentinel.py --fail-on high || echo "hardening regression!"
```

## What it checks

| Category         | Examples |
|------------------|----------|
| **Filesystem**   | permissions on `/etc/shadow`, `/etc/sudoers`; home-dir exposure; SSH private-key modes; world-writable files; unexpected SUID/SGID binaries |
| **Accounts**     | non-root UID 0 accounts; empty-password accounts; service accounts with interactive shells |
| **SSH**          | `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, protocol version; `authorized_keys` review |
| **Network**      | listening services bound beyond loopback; risky ports (Telnet, Redis, Docker API, databases…) exposed externally |
| **Kernel**       | ASLR, reverse-path filtering, TCP SYN cookies |
| **Environment**  | writable / relative `$PATH` entries; unsafe `umask` |
| **Scheduled**    | group/world-writable cron jobs |

## Scoring

Each finding carries a severity (`LOW`→`CRITICAL`) that contributes risk
points. The total is capped at 100 and mapped to a letter grade:

| Score  | Grade |
|--------|-------|
| 0      | A+ |
| 1–8    | A  |
| 9–20   | B  |
| 21–40  | C  |
| 41–65  | D  |
| 66+    | F  |

## Project layout

```
nox_sentinel.py          CLI entry point
sentinel/
  core.py                Severity, Finding, Report + scoring
  engine.py              runs checks, aggregates findings
  ui.py                  colors, banner, dashboard rendering
  checks/
    base.py              Check base class + helpers
    filesystem.py        permission & SUID checks
    accounts.py          passwd / shadow checks
    ssh.py               sshd_config hardening
    network.py           listening-socket exposure (via /proc)
    kernel.py            sysctl & environment hardening
    cron.py              scheduled-task checks
tests/
  test_sentinel.py       unit tests (python3 -m unittest discover -s tests)
```

## Extending

Add a check by subclassing `Check`, giving it an `id`, `category`, `title`,
and a `run()` that yields `Finding` objects, then register it in
`sentinel/checks/__init__.py`. The base class provides `self.finding(...)` and
`self.ok(...)` helpers, and any exception a check raises is caught and turned
into a non-fatal note so one broken check can never abort the audit.

## Tests

```bash
python3 -m unittest discover -s tests
```

## Scope & ethics

Nox Sentinel is a **defensive** tool intended to be run on hosts you own or
are authorised to assess. It reports weaknesses and how to fix them; it does
not exploit anything and makes no changes.

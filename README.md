# Nox Sentinel
<img width="429" height="452" alt="Captura de pantalla 2026-08-27 164452" src="https://github.com/user-attachments/assets/2acf7a65-35fc-48ba-a76e-96cee3df7637" />

**A multi-platform local security auditor & threat inspector.** Nox Sentinel
inspects the machine it runs on for hardening weaknesses, indicators of
compromise (IOC), malware persistence mechanisms, cookie and credential
exposures, and system vulnerabilities — then scores overall risk and renders
a clean terminal dashboard.

It is **passive and read-only**: every check merely observes the system. Nox
Sentinel never changes a file, never touches the network, and never runs an
external modifying command. It depends only on the Python standard library.

## Supported Platforms

| Platform | Support | Notes |
|---|---|---|
| **Linux** | Full | Deep inspection via `/proc`, system configs, kernel baselines, services, crons. |
| **Termux (Android)** | Full | Runs out of the box in Termux terminal under Android (POSIX environment). |
| **Windows** | Full | Native inspection via `winreg` (Defender, Firewall, UAC, AutoRun, RDP, credentials). |
| **macOS** | Basic / Partial | Cross-platform checks (Crypto, Browser/Cookies, SSH keys, `.env` files). |

## Quick start

No install, no third-party dependencies:

```bash
python3 nox_sentinel.py       # On Linux / Termux / macOS
python nox_sentinel.py        # On Windows
```

That runs the full audit and prints the dashboard. Some checks (e.g. reading
`/etc/shadow` on Linux) reveal more when run as root / administrator, but the
tool works fine as an unprivileged user and notes what it could not inspect.

## Usage

```bash
python nox_sentinel.py                      # full audit, colored dashboard
python nox_sentinel.py --show-ok            # also show checks that passed
python nox_sentinel.py -w 5                 # continuous watch mode (audit every 5s)
python nox_sentinel.py -c malware -c browser # only selected categories
python nox_sentinel.py --json               # machine-readable report
python nox_sentinel.py -o report.json       # save JSON to a file
python nox_sentinel.py --fail-on high       # exit non-zero for CI gating
python nox_sentinel.py --list-checks        # show what would run
python nox_sentinel.py --no-color           # plain text
```

### Continuous Watch Mode

`--watch [SECS]` (or `-w`) keeps Nox Sentinel actively monitoring the system in
real time, alerting whenever the risk score or findings change:

```bash
python nox_sentinel.py --watch 5
```

### CI / Build Gating

`--fail-on` makes Nox Sentinel a build gate. It exits `1` when any finding
reaches the given severity, so a pipeline can block a host that regresses:

```bash
python nox_sentinel.py --fail-on high || echo "hardening regression!"
```

## What it checks

| Category | Description & Examples |
|---|---|
| **Malware / IOC** | Processes running from deleted binaries (`(deleted)` exe links), hidden items in `/tmp` / `/dev/shm`, code execution mapped from temp storage, recently modified system binaries |
| **Persistence** | Suspicious cron pipelines (`curl\|sh`, `nc -e`, `base64 -d`), `LD_PRELOAD` / `/etc/ld.so.preload` hooks, reverse shell injections in shell profiles (`.bashrc`), rogue systemd units |
| **Browser & Cookies** | SQLite cookie databases for Chrome, Chromium, Edge, Brave, Firefox; unencrypted cookies for sensitive domains (banking, Google, GitHub); Firefox master password protection |
| **Crypto & Secrets** | Weak SSH keys (deprecated DSA, RSA < 2048), world-readable `.env` / credentials files, plaintext passwords in `.docker/config.json`, `.netrc`, `.aws/credentials` |
| **Windows Native** | Windows Defender Real-Time Protection status, Firewall state across all network profiles, UAC (EnableLUA), AutoRun/AutoPlay USB policy, RDP exposure |
| **Filesystem** | Permissions on `/etc/shadow`, `/etc/sudoers`; home-dir exposure; SSH private-key modes; world-writable files; unexpected SUID/SGID binaries |
| **Accounts** | Non-root UID 0 accounts; empty-password accounts; service accounts with interactive shells |
| **SSH** | `PermitRootLogin`, `PasswordAuthentication`, `PermitEmptyPasswords`, protocol version; `authorized_keys` review |
| **Network** | Listening services bound beyond loopback; risky ports (Telnet, Redis, Docker API, databases…); promiscuous sniffer interfaces (IFF_PROMISC); `/etc/hosts` DNS hijacking; active outbound sessions |
| **Kernel & Env** | ASLR, reverse-path filtering, TCP SYN cookies; writable / relative `$PATH` entries; unsafe `umask` |
| **Forensics** | Truncated / wiped audit logs (`auth.log`, `secure`), cleared shell history files (`.bash_history` -> `/dev/null`), timestomped files with future timestamps, missing sticky bit on `/tmp` |
| **Packages** | Kernel vulnerability baseline against critical CVEs (Dirty Pipe CVE-2022-0847, Dirty COW CVE-2016-5195); automatic security update configuration |

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
nox_sentinel.py          CLI entry point & watch engine
sentinel/
  core.py                Severity, Finding, Report + scoring
  engine.py              runs checks, aggregates findings
  ui.py                  colors, banner, dashboard & priority recommendations
  checks/
    base.py              Check base class + platform helpers
    malware.py           IOC heuristics & deleted process binaries
    persistence.py       cron, systemd, shell profiles, ld.so.preload
    browser.py           browser cookie store audit & profile security
    crypto.py            weak SSH keys, .env exposure, plaintext credentials
    windows.py           Windows Defender, Firewall, UAC, AutoRun, RDP
    filesystem.py        permission & SUID checks
    accounts.py          passwd / shadow checks
    ssh.py               sshd_config hardening
    network.py           listening-socket exposure (via /proc)
    network_advanced.py  promiscuous sniffers, hosts hijack, outbound sessions
    kernel.py            sysctl & environment hardening
    cron.py              scheduled-task checks
    forensics.py         wiped logs, history tampering, timestomping
    packages.py          kernel CVE baseline, automatic updates
tests/
  test_sentinel.py       comprehensive cross-platform unit test suite
```

## Running Tests

```bash
python -m unittest discover -s tests
```

## Scope & ethics

Nox Sentinel is a **defensive** tool intended to be run on hosts you own or
are authorised to assess. It reports weaknesses and how to fix them; it does
not exploit anything and makes no destructive changes.

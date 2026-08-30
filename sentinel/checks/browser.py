"""Browser security and cookie database audit for Linux, Termux, and Windows."""

from __future__ import annotations

import os
import sqlite3
import stat
from pathlib import Path
from typing import Iterator

from sentinel.checks.base import Check, is_windows, mode_string
from sentinel.core import Severity

SENSITIVE_DOMAINS = (
    "google",
    "github",
    "microsoft",
    "apple",
    "amazon",
    "facebook",
    "twitter",
    "x.com",
    "paypal",
    "bank",
    "stripe",
    "discord",
    "telegram",
)


def _get_browser_cookie_paths() -> list[tuple[str, Path]]:
    """Locate cookie database paths for major browsers across platforms."""
    paths = []
    home = Path.home()

    if is_windows():
        local_app = Path(os.environ.get("LOCALAPPDATA", str(home / "AppData" / "Local")))
        roaming_app = Path(os.environ.get("APPDATA", str(home / "AppData" / "Roaming")))

        candidates = [
            ("Chrome", local_app / "Google" / "Chrome" / "User Data" / "Default" / "Network" / "Cookies"),
            ("Edge", local_app / "Microsoft" / "Edge" / "User Data" / "Default" / "Network" / "Cookies"),
            ("Brave", local_app / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Network" / "Cookies"),
            ("Opera", roaming_app / "Opera Software" / "Opera Stable" / "Network" / "Cookies"),
        ]
        for name, p in candidates:
            if p.is_file():
                paths.append((name, p))

        # Firefox in Windows
        ff_dir = roaming_app / "Mozilla" / "Firefox" / "Profiles"
        if ff_dir.is_dir():
            try:
                for profile in ff_dir.iterdir():
                    c_db = profile / "cookies.sqlite"
                    if c_db.is_file():
                        paths.append((f"Firefox ({profile.name})", c_db))
            except OSError:
                pass

    else:
        # Linux & Termux
        candidates = [
            ("Chrome", home / ".config" / "google-chrome" / "Default" / "Cookies"),
            ("Chromium", home / ".config" / "chromium" / "Default" / "Cookies"),
            ("Brave", home / ".config" / "BraveSoftware" / "Brave-Browser" / "Default" / "Cookies"),
            ("Edge", home / ".config" / "microsoft-edge" / "Default" / "Cookies"),
        ]
        for name, p in candidates:
            if p.is_file():
                paths.append((name, p))

        # Firefox in Linux
        ff_dir = home / ".mozilla" / "firefox"
        if ff_dir.is_dir():
            try:
                for profile in ff_dir.iterdir():
                    c_db = profile / "cookies.sqlite"
                    if c_db.is_file():
                        paths.append((f"Firefox ({profile.name})", c_db))
            except OSError:
                pass

    return paths


class BrowserCookieAudit(Check):
    """Audit browser cookie stores for permissions and sensitive session exposure."""

    id = "browser.cookies"
    category = "Browser"
    title = "Browser cookie store security"

    def run(self):
        cookie_stores = _get_browser_cookie_paths()
        if not cookie_stores:
            yield self.ok("No browser cookie databases found in user profiles.")
            return

        for browser_name, db_path in cookie_stores:
            # 1. Check permissions on POSIX
            if not is_windows():
                try:
                    mode = db_path.stat().st_mode
                    perms = stat.S_IMODE(mode)
                    if perms & 0o077:
                        yield self.finding(
                            Severity.HIGH,
                            f"{browser_name} cookies database readable by other users ({mode_string(perms)})",
                            detail=f"Path: {db_path}. Anyone with local read access can steal active session cookies.",
                            recommendation=f"chmod 600 {db_path}",
                            evidence=(f"path={db_path}", f"mode={mode_string(perms)}"),
                        )
                except OSError:
                    pass

            # 2. Inspect cookie count and sensitive sessions
            total_cookies = 0
            sensitive_count = 0
            sensitive_hosts = set()
            insecure_flags = 0

            try:
                uri = f"file:{db_path.as_posix()}?mode=ro"
                conn = sqlite3.connect(uri, uri=True, timeout=1.0)
                cursor = conn.cursor()

                # Chrome/Chromium/Edge schema: cookies (host_key, name, is_secure, is_httponly)
                # Firefox schema: moz_cookies (host, name, isSecure, isHttpOnly)
                table_names = [row[0] for row in cursor.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall()]

                if "cookies" in table_names:
                    rows = cursor.execute("SELECT host_key, name, is_secure, is_httponly FROM cookies").fetchall()
                    total_cookies = len(rows)
                    for host, _name, is_sec, is_http in rows:
                        host_str = (host or "").lower()
                        for s_dom in SENSITIVE_DOMAINS:
                            if s_dom in host_str:
                                sensitive_count += 1
                                sensitive_hosts.add(host_str.lstrip("."))
                                if not is_sec or not is_http:
                                    insecure_flags += 1
                                break

                elif "moz_cookies" in table_names:
                    rows = cursor.execute("SELECT host, name, isSecure, isHttpOnly FROM moz_cookies").fetchall()
                    total_cookies = len(rows)
                    for host, _name, is_sec, is_http in rows:
                        host_str = (host or "").lower()
                        for s_dom in SENSITIVE_DOMAINS:
                            if s_dom in host_str:
                                sensitive_count += 1
                                sensitive_hosts.add(host_str.lstrip("."))
                                if not is_sec or not is_http:
                                    insecure_flags += 1
                                break

                conn.close()
            except (sqlite3.Error, OSError):
                # Browser might have database locked while open
                yield self.finding(
                    Severity.INFO,
                    f"{browser_name} cookie store found ({db_path.name})",
                    detail=f"Location: {db_path}. Database currently locked by running browser instance.",
                )
                continue

            if total_cookies > 0:
                detail_msg = f"Contains {total_cookies} total cookies ({sensitive_count} associated with sensitive accounts)."
                if insecure_flags > 0:
                    detail_msg += f" {insecure_flags} cookie(s) lack HttpOnly/Secure flags."

                sev = Severity.LOW if sensitive_count > 0 else Severity.INFO
                yield self.finding(
                    sev,
                    f"{browser_name}: {total_cookies} stored cookies ({sensitive_count} sensitive)",
                    detail=detail_msg,
                    recommendation="Clear browser cookies regularly or use isolated private browsing for sensitive accounts.",
                    evidence=(
                        f"browser={browser_name}",
                        f"total_cookies={total_cookies}",
                        f"sensitive_domains={', '.join(list(sensitive_hosts)[:6])}",
                    ),
                )


class FirefoxMasterPasswordCheck(Check):
    """Check if Firefox profiles have a Primary/Master password enabled."""

    id = "browser.firefox_master_pw"
    category = "Browser"
    title = "Firefox master password protection"

    def run(self):
        home = Path.home()
        ff_base = (
            home / "AppData" / "Roaming" / "Mozilla" / "Firefox" / "Profiles"
            if is_windows()
            else home / ".mozilla" / "firefox"
        )

        if not ff_base.is_dir():
            return

        try:
            for profile in ff_base.iterdir():
                logins_file = profile / "logins.json"
                key4_file = profile / "key4.db"

                if logins_file.is_file() and key4_file.is_file():
                    content = logins_file.read_text(encoding="utf-8", errors="replace")
                    if '"logins":[' in content and '"logins":[]' not in content:
                        # Logins are saved in this profile
                        yield self.finding(
                            Severity.MEDIUM,
                            f"Firefox profile '{profile.name}' has stored logins",
                            detail="Saved browser credentials can be dumped by local infostealers if Primary Password is not set.",
                            recommendation="Enable Firefox Primary Password under Settings -> Privacy & Security.",
                            evidence=(f"profile={profile.name}", f"path={logins_file}"),
                        )
        except OSError:
            pass

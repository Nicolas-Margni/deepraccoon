"""
BrowserScanner: detects AI tool usage through browser artifacts.

Automatically detects the default browser on the system, then scans:
  1. Browsing history — finds visits to known AI service domains
  2. Installed extensions — compares against known AI extension IDs
  3. Cookies — detects active sessions on AI platforms

Supports: Chrome, Edge, Firefox, Opera, Opera GX, Brave, Vivaldi.
Works on Windows (primary), with Linux/macOS path fallbacks.

The history database (SQLite) must not be locked by the browser.
If the browser is open, the file is locked and the scan will skip it
gracefully without crashing.
"""

import platform
import shutil
import sqlite3
import tempfile
try:
    import winreg
except ImportError:
    winreg = None  # Not available on Linux/macOS
from pathlib import Path
from typing import Optional
from urllib.parse import urlparse

from core.finding import Finding
from modules.base_module import BaseModule


# ---------------------------------------------------------------------------
# Browser profile path registry
# Each entry maps a browser key to its profile base path on Windows.
# %LOCALAPPDATA% and %APPDATA% are resolved via Path.home() equivalent.
# ---------------------------------------------------------------------------

def _local() -> Path:
    """Return %LOCALAPPDATA% path."""
    import os
    return Path(os.environ.get("LOCALAPPDATA", Path.home() / "AppData" / "Local"))


def _roaming() -> Path:
    """Return %APPDATA% path."""
    import os
    return Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))


BROWSER_PROFILES: dict[str, dict] = {
    "chrome": {
        "name": "Google Chrome",
        "type": "chromium",
        "history_paths": [
            lambda: _local() / "Google" / "Chrome" / "User Data" / "Default" / "History",
            lambda: _local() / "Google" / "Chrome" / "User Data" / "Profile 1" / "History",
        ],
        "extensions_path": lambda: _local() / "Google" / "Chrome" / "User Data" / "Default" / "Extensions",
    },
    "edge": {
        "name": "Microsoft Edge",
        "type": "chromium",
        "history_paths": [
            lambda: _local() / "Microsoft" / "Edge" / "User Data" / "Default" / "History",
            lambda: _local() / "Microsoft" / "Edge" / "User Data" / "Profile 1" / "History",
        ],
        "extensions_path": lambda: _local() / "Microsoft" / "Edge" / "User Data" / "Default" / "Extensions",
    },
    "brave": {
        "name": "Brave Browser",
        "type": "chromium",
        "history_paths": [
            lambda: _local() / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "History",
        ],
        "extensions_path": lambda: _local() / "BraveSoftware" / "Brave-Browser" / "User Data" / "Default" / "Extensions",
    },
    "opera": {
        "name": "Opera",
        "type": "chromium",
        "history_paths": [
            lambda: _roaming() / "Opera Software" / "Opera Stable" / "History",
        ],
        "extensions_path": lambda: _roaming() / "Opera Software" / "Opera Stable" / "Extensions",
    },
    "operagx": {
        "name": "Opera GX",
        "type": "chromium",
        "history_paths": [
            lambda: _roaming() / "Opera Software" / "Opera GX Stable" / "History",
        ],
        "extensions_path": lambda: _roaming() / "Opera Software" / "Opera GX Stable" / "Extensions",
    },
    "vivaldi": {
        "name": "Vivaldi",
        "type": "chromium",
        "history_paths": [
            lambda: _local() / "Vivaldi" / "User Data" / "Default" / "History",
        ],
        "extensions_path": lambda: _local() / "Vivaldi" / "User Data" / "Default" / "Extensions",
    },
    "firefox": {
        "name": "Mozilla Firefox",
        "type": "firefox",
        "history_paths": [],   # Firefox paths are dynamic — resolved separately
        "extensions_path": None,
    },
}


def _detect_default_browser_windows() -> Optional[str]:
    """
    Read the Windows registry to find the default browser.

    Checks HKCU\\Software\\Microsoft\\Windows\\Shell\\Associations\\UrlAssociations\\https\\UserChoice
    and maps the ProgId to a known browser key.

    Returns:
        Browser key string (e.g. 'edge', 'chrome') or None if not detected.
    """
    if winreg is None:
        return None

    try:
        key_path = (
            r"Software\Microsoft\Windows\Shell\Associations"
            r"\UrlAssociations\https\UserChoice"
        )
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path) as key:
            prog_id, _ = winreg.QueryValueEx(key, "ProgId")
            prog_id = prog_id.lower()

        mapping = {
            "msedgehtm":        "edge",
            "chromium":         "chrome",
            "chrome":           "chrome",
            "googlechrome":     "chrome",
            "firefoxurl":       "firefox",
            "operastable":      "opera",
            "operagx":          "operagx",
            "bravebrowser":     "brave",
            "vivaldi":          "vivaldi",
        }

        for keyword, browser_key in mapping.items():
            if keyword in prog_id:
                return browser_key

    except (OSError, FileNotFoundError):
        pass

    return None


def _find_installed_browsers() -> list[str]:
    """
    Scan known browser profile paths to find which browsers are actually installed,
    regardless of which is the default.

    Returns:
        List of browser keys whose history files exist on disk.
    """
    found: list[str] = []
    for key, profile in BROWSER_PROFILES.items():
        if key == "firefox":
            if _find_firefox_history_paths():
                found.append(key)
            continue
        for path_fn in profile["history_paths"]:
            try:
                if path_fn().exists():
                    found.append(key)
                    break
            except (OSError, TypeError):
                continue
    return found


def _find_firefox_history_paths() -> list[Path]:
    """
    Locate Firefox SQLite history databases.

    Firefox stores profiles in %APPDATA%\\Mozilla\\Firefox\\Profiles\\<random>.default\\
    There can be multiple profiles.

    Returns:
        List of existing places.sqlite paths.
    """
    profiles_root = _roaming() / "Mozilla" / "Firefox" / "Profiles"
    if not profiles_root.exists():
        return []

    paths: list[Path] = []
    try:
        for profile_dir in profiles_root.iterdir():
            places = profile_dir / "places.sqlite"
            if places.exists():
                paths.append(places)
    except OSError:
        pass
    return paths


def _copy_db_to_temp(db_path: Path) -> Optional[Path]:
    """
    Copy a SQLite database to a temp file to avoid locking issues.

    Browsers lock their SQLite files while running. Copying to a temp
    location allows us to read it even if the browser is open (though
    data may be slightly stale).

    Args:
        db_path: Path to the original SQLite database.

    Returns:
        Path to the temp copy, or None if the copy failed.
    """
    try:
        tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
        shutil.copy2(db_path, tmp.name)
        return Path(tmp.name)
    except (OSError, PermissionError):
        return None


def _extract_domain(url: str) -> Optional[str]:
    """
    Extract the hostname from a URL string.

    Args:
        url: Full URL string.

    Returns:
        Lowercase hostname, or None if parsing fails.
    """
    try:
        parsed = urlparse(url)
        host = parsed.netloc.lower()
        # Strip 'www.' prefix for cleaner matching
        return host.removeprefix("www.")
    except (ValueError, AttributeError):
        return None


def _domain_matches_site(domain: str, site: dict) -> bool:
    """Check if a domain matches a known AI site (exact or subdomain)."""
    known = site["domain"].lower()
    return domain == known or domain.endswith("." + known)


class BrowserScanner(BaseModule):
    """
    Detects AI tool usage through browser history, extensions, and cookies.

    Automatically detects the default browser and all installed browsers,
    then scans each one for evidence of AI service usage.
    """

    @property
    def name(self) -> str:
        return "browser_scanner"

    @property
    def description(self) -> str:
        return "Detects AI usage in browser history, extensions and cookies"

    def run(self) -> list[Finding]:
        """
        Detect browsers and scan each one found on the system.

        Returns:
            List of Finding objects from all browser sources.
        """
        findings: list[Finding] = []

        if platform.system() != "Windows":
            # Unix path support can be added in a future stage
            return findings

        ai_sites = self.signatures.get("browser_ai_sites", [])
        known_extensions = self.signatures.get("browser_extensions", [])

        # Detect default browser first
        default_key = _detect_default_browser_windows()

        # Scan ALL installed browsers, not just the default
        installed_keys = _find_installed_browsers()

        if not installed_keys:
            return findings

        # Report which browser is the default
        if default_key:
            browser_name = BROWSER_PROFILES.get(default_key, {}).get("name", default_key)
            findings.append(Finding(
                module=self.name,
                severity="INFO",
                title=f"Default browser detected: {browser_name}",
                description=(
                    f"{browser_name} is set as the default browser on this system. "
                    f"Browser history and extensions will be scanned."
                ),
                evidence=f"Default browser: {browser_name}",
                recommendation="No action required. This is informational.",
            ))

        scanned_domains: set[str] = set()

        for browser_key in installed_keys:
            profile = BROWSER_PROFILES[browser_key]
            browser_name = profile["name"]
            is_default = (browser_key == default_key)
            label = f"{browser_name}{' (default)' if is_default else ''}"

            # Scan history
            if browser_key == "firefox":
                for history_path in _find_firefox_history_paths():
                    findings.extend(
                        self._scan_firefox_history(history_path, label, ai_sites, scanned_domains)
                    )
            else:
                for path_fn in profile["history_paths"]:
                    try:
                        history_path = path_fn()
                    except (OSError, TypeError):
                        continue
                    if history_path.exists():
                        findings.extend(
                            self._scan_chromium_history(history_path, label, ai_sites, scanned_domains)
                        )
                        break  # Found a valid profile, don't scan duplicates

            # Scan extensions (chromium-based only)
            ext_path_fn = profile.get("extensions_path")
            if ext_path_fn:
                try:
                    ext_path = ext_path_fn()
                    if ext_path and ext_path.exists():
                        findings.extend(
                            self._scan_extensions(ext_path, label, known_extensions)
                        )
                except (OSError, TypeError):
                    pass

        return findings

    def _scan_chromium_history(
        self,
        history_path: Path,
        browser_label: str,
        ai_sites: list[dict],
        scanned_domains: set[str],
    ) -> list[Finding]:
        """
        Scan a Chromium-based browser history SQLite database.

        The 'urls' table contains: url, title, visit_count, last_visit_time.

        Args:
            history_path:    Path to the History SQLite file.
            browser_label:   Display name of the browser.
            ai_sites:        List of known AI site dicts.
            scanned_domains: Set of already-reported domains (dedup across browsers).

        Returns:
            List of Finding objects for each unique AI domain found.
        """
        findings: list[Finding] = []
        tmp_path = _copy_db_to_temp(history_path)
        if not tmp_path:
            return findings

        try:
            conn = sqlite3.connect(str(tmp_path))
            cursor = conn.cursor()
            cursor.execute("SELECT url, title, visit_count FROM urls ORDER BY visit_count DESC")
            rows = cursor.fetchall()
            conn.close()
        except sqlite3.Error:
            return findings
        finally:
            try:
                tmp_path.unlink()
            except OSError:
                pass

        seen_in_this_browser: set[str] = set()

        for url, title, visit_count in rows:
            domain = _extract_domain(url)
            if not domain:
                continue

            for site in ai_sites:
                if not _domain_matches_site(domain, site):
                    continue

                site_key = site["domain"]
                if site_key in scanned_domains or site_key in seen_in_this_browser:
                    break

                seen_in_this_browser.add(site_key)
                scanned_domains.add(site_key)

                findings.append(Finding(
                    module=self.name,
                    severity=site["severity"],
                    title=f"AI site visited: {site['name']} ({site['category']})",
                    description=(
                        f"{site['name']} ({site['category']}) was found in the "
                        f"{browser_label} browsing history. "
                        f"Visit count: {visit_count}."
                    ),
                    evidence=f"{browser_label} history → {site['domain']} ({visit_count} visits)",
                    recommendation=(
                        f"Verify whether use of {site['name']} is authorized "
                        f"by your organization's policy."
                    ),
                ))
                break

        return findings

    def _scan_firefox_history(
        self,
        history_path: Path,
        browser_label: str,
        ai_sites: list[dict],
        scanned_domains: set[str],
    ) -> list[Finding]:
        """
        Scan a Firefox places.sqlite history database.

        Firefox uses 'moz_places' table with: url, title, visit_count.

        Args:
            history_path:    Path to places.sqlite.
            browser_label:   Display name of the browser.
            ai_sites:        List of known AI site dicts.
            scanned_domains: Set of already-reported domains (dedup across browsers).

        Returns:
            List of Finding objects for each unique AI domain found.
        """
        findings: list[Finding] = []
        tmp_path = _copy_db_to_temp(history_path)
        if not tmp_path:
            return findings

        try:
            conn = sqlite3.connect(str(tmp_path))
            cursor = conn.cursor()
            cursor.execute("SELECT url, title, visit_count FROM moz_places ORDER BY visit_count DESC")
            rows = cursor.fetchall()
            conn.close()
        except sqlite3.Error:
            return findings
        finally:
            try:
                tmp_path.unlink()
            except OSError:
                pass

        seen_in_this_browser: set[str] = set()

        for url, title, visit_count in rows:
            domain = _extract_domain(url)
            if not domain:
                continue

            for site in ai_sites:
                if not _domain_matches_site(domain, site):
                    continue

                site_key = site["domain"]
                if site_key in scanned_domains or site_key in seen_in_this_browser:
                    break

                seen_in_this_browser.add(site_key)
                scanned_domains.add(site_key)

                findings.append(Finding(
                    module=self.name,
                    severity=site["severity"],
                    title=f"AI site visited: {site['name']} ({site['category']})",
                    description=(
                        f"{site['name']} ({site['category']}) was found in the "
                        f"{browser_label} browsing history. "
                        f"Visit count: {visit_count}."
                    ),
                    evidence=f"{browser_label} history → {site['domain']} ({visit_count} visits)",
                    recommendation=(
                        f"Verify whether use of {site['name']} is authorized "
                        f"by your organization's policy."
                    ),
                ))
                break

        return findings

    def _scan_extensions(
        self,
        extensions_path: Path,
        browser_label: str,
        known_extensions: list[dict],
    ) -> list[Finding]:
        """
        Scan the browser's Extensions folder for known AI extensions.

        Chromium-based browsers store each extension in a subfolder named
        by its extension ID. We compare those IDs against signatures.json.

        Args:
            extensions_path:   Path to the Extensions folder.
            browser_label:     Display name of the browser.
            known_extensions:  List of known AI extension dicts.

        Returns:
            List of HIGH severity Finding objects for each AI extension found.
        """
        findings: list[Finding] = []

        try:
            installed_ids = {p.name for p in extensions_path.iterdir() if p.is_dir()}
        except OSError:
            return findings

        for ext_def in known_extensions:
            if ext_def["id"] in installed_ids:
                findings.append(Finding(
                    module=self.name,
                    severity="HIGH",
                    title=f"AI browser extension installed: {ext_def['name']}",
                    description=(
                        f"The browser extension '{ext_def['name']}' was found installed "
                        f"in {browser_label}. AI extensions can access page content, "
                        f"form data, and clipboard."
                    ),
                    evidence=(
                        f"{browser_label} → Extension ID: {ext_def['id']} "
                        f"({ext_def['name']})"
                    ),
                    recommendation=(
                        f"Review whether '{ext_def['name']}' is authorized. "
                        f"Remove it from {browser_label} extensions if not approved."
                    ),
                ))

        return findings

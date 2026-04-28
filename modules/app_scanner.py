"""
AppScanner: detects AI applications installed directly on the system.

Unlike browser visits (LOW severity), installed AI apps represent a deeper
level of integration — the user deliberately installed the tool, it may
run in the background, and it may have system-level access.

Detection strategies (Windows-primary):
  1. Executable path check — looks for known .exe paths on disk
  2. Windows registry — checks Uninstall keys for known app names
  3. Start Menu shortcuts — scans for .lnk files with AI app names

Each detected installed app generates a MEDIUM severity finding.
"""

import os
import platform
import re
from pathlib import Path
from typing import Optional

from core.finding import Finding
from modules.base_module import BaseModule


def _expand_vars(path_str: str) -> Path:
    """
    Expand Windows environment variables in a path string and return a Path.

    Handles %LOCALAPPDATA%, %APPDATA%, %USERPROFILE% and any %VAR% style variable.

    Args:
        path_str: Raw path string with optional %VAR% tokens.

    Returns:
        Resolved Path object.
    """
    def _replace(match: re.Match) -> str:
        return os.environ.get(match.group(1), match.group(0))

    expanded = re.sub(r"%([^%]+)%", _replace, path_str)
    return Path(expanded)


def _check_registry_installed(app_name: str) -> Optional[str]:
    """
    Check the Windows Uninstall registry keys for a given app name.

    Scans both HKCU and HKLM uninstall hives for a DisplayName matching
    the app name (case-insensitive substring match).

    Args:
        app_name: Application name to search for.

    Returns:
        DisplayName string if found, None otherwise.
    """
    try:
        import winreg
    except ImportError:
        return None

    hives = [
        (winreg.HKEY_CURRENT_USER,  r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Uninstall"),
        (winreg.HKEY_LOCAL_MACHINE, r"Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"),
    ]

    search_name = app_name.lower()

    for hive, key_path in hives:
        try:
            with winreg.OpenKey(hive, key_path) as uninstall_key:
                i = 0
                while True:
                    try:
                        sub_key_name = winreg.EnumKey(uninstall_key, i)
                        with winreg.OpenKey(uninstall_key, sub_key_name) as sub_key:
                            try:
                                display_name, _ = winreg.QueryValueEx(sub_key, "DisplayName")
                                if search_name in display_name.lower():
                                    return display_name
                            except FileNotFoundError:
                                pass
                        i += 1
                    except OSError:
                        break
        except (OSError, FileNotFoundError):
            continue

    return None


def _check_start_menu(app_name: str) -> Optional[Path]:
    """
    Search Start Menu folders for shortcuts matching the app name.

    Args:
        app_name: Application name to search for (case-insensitive).

    Returns:
        Path to the shortcut if found, None otherwise.
    """
    start_menu_paths = []

    appdata = os.environ.get("APPDATA", "")
    programdata = os.environ.get("PROGRAMDATA", "C:\\ProgramData")

    if appdata:
        start_menu_paths.append(
            Path(appdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
        )
    start_menu_paths.append(
        Path(programdata) / "Microsoft" / "Windows" / "Start Menu" / "Programs"
    )

    search_name = app_name.lower()

    for start_path in start_menu_paths:
        if not start_path.exists():
            continue
        try:
            for lnk in start_path.rglob("*.lnk"):
                if search_name in lnk.stem.lower():
                    return lnk
        except OSError:
            continue

    return None


class AppScanner(BaseModule):
    """
    Detects AI applications installed directly on the Windows system.

    Checks executable paths, Windows registry uninstall entries, and
    Start Menu shortcuts. Each installed AI app is reported as MEDIUM
    severity — it represents deliberate installation, not just web usage.
    """

    @property
    def name(self) -> str:
        return "app_scanner"

    @property
    def description(self) -> str:
        return "Detects AI applications installed directly on the system"

    def run(self) -> list[Finding]:
        """
        Scan for installed AI applications using multiple detection strategies.

        Returns:
            List of MEDIUM severity Finding objects, one per detected app.
        """
        if platform.system() != "Windows":
            return []

        findings: list[Finding] = []
        known_apps = self.signatures.get("installed_apps", [])
        already_reported: set[str] = set()

        for app_def in known_apps:
            app_name = app_def["name"]

            if app_name in already_reported:
                continue

            evidence = self._detect_app(app_def)
            if not evidence:
                continue

            already_reported.add(app_name)

            findings.append(Finding(
                module=self.name,
                severity="MEDIUM",
                title=f"AI application installed: {app_name}",
                description=(
                    f"{app_def['description']} was found installed on this system. "
                    f"Installed AI apps may run in the background, sync data to "
                    f"external servers, and have broader system access than browser-based usage."
                ),
                evidence=evidence,
                recommendation=(
                    f"Verify whether '{app_name}' is authorized by your organization's policy. "
                    f"If not, uninstall it via Settings → Apps, and check for any associated "
                    f"data folders or configuration files left behind."
                ),
            ))

        return findings

    def _detect_app(self, app_def: dict) -> Optional[str]:
        """
        Try all detection strategies for a single app definition.

        Tries in order:
        1. Known executable paths from signatures.json
        2. Windows registry uninstall keys
        3. Start Menu shortcuts

        Args:
            app_def: App definition dict from signatures.json.

        Returns:
            Evidence string if the app is detected, None otherwise.
        """
        app_name = app_def["name"]

        # Strategy 1: Check known executable paths
        for path_str in app_def.get("paths", []):
            try:
                resolved = _expand_vars(path_str)
                if resolved.exists():
                    return f"Executable found: {resolved}"
            except (OSError, ValueError):
                continue

        # Strategy 2: Windows registry
        registry_name = _check_registry_installed(app_name)
        if registry_name:
            return f"Registry entry: {registry_name}"

        # Strategy 3: Start Menu shortcut
        shortcut = _check_start_menu(app_name)
        if shortcut:
            return f"Start Menu shortcut: {shortcut}"

        return None

"""
EnvScanner: detects AI service API keys exposed in:
  - Active system and user environment variables (os.environ)
  - .env files in the current directory and user home
  - Shell profile files: .bashrc, .zshrc, .profile (Linux/macOS)

Detected keys are redacted in the report — only the first 12 characters
are shown to avoid exposing real credentials.
"""

import os
import re
from pathlib import Path

from core.finding import Finding
from modules.base_module import BaseModule


def _redact(key_value: str) -> str:
    """
    Redact an API key for the report, showing only the first 12 characters.

    Args:
        key_value: Full key value.

    Returns:
        Redacted string like 'sk-proj-aaaa...[REDACTED]'
    """
    if len(key_value) <= 12:
        return "[REDACTED]"
    return key_value[:12] + "...[REDACTED]"


def _build_finding(
    module_name: str,
    provider: str,
    severity: str,
    source: str,
    var_name: str,
    redacted_value: str,
) -> Finding:
    """Build a standardized Finding for a detected API key."""
    return Finding(
        module=module_name,
        severity=severity,
        title=f"{provider} API key exposed",
        description=(
            f"A {provider} API key was found in {source}. "
            f"Keys exposed in the environment can be accessed by "
            f"any process running on this system."
        ),
        evidence=f"{source} → {var_name} = {redacted_value}",
        recommendation=(
            f"Remove the key '{var_name}' from {source}. "
            f"Use a secrets manager (such as Windows Credential Manager or "
            f"a .env file outside the repository with .gitignore) instead. "
            f"Rotate the key in the provider dashboard if it was exposed."
        ),
    )


class EnvScanner(BaseModule):
    """
    Detects AI service API keys in environment variables and config files.

    Scans:
    1. Active environment variables (os.environ)
    2. .env files in the current directory and user home
    3. Shell profile files (.bashrc, .zshrc, .profile) on Unix systems
    """

    @property
    def name(self) -> str:
        return "env_scanner"

    @property
    def description(self) -> str:
        return "Detects AI API keys in environment variables and .env files"

    def run(self) -> list[Finding]:
        """
        Execute all environment variable sub-scans.

        Returns:
            List of Finding objects with all detected keys.
        """
        findings: list[Finding] = []
        patterns = self.signatures.get("api_key_patterns", [])

        findings.extend(self._scan_environ(patterns))
        findings.extend(self._scan_env_files(patterns))
        findings.extend(self._scan_shell_profiles(patterns))

        return findings

    def _scan_environ(self, patterns: list[dict]) -> list[Finding]:
        """Scan active environment variables of the current process."""
        findings: list[Finding] = []

        for var_name, var_value in os.environ.items():
            for pattern_def in patterns:
                try:
                    match = re.search(pattern_def["pattern"], var_value)
                    if match:
                        findings.append(_build_finding(
                            module_name=self.name,
                            provider=pattern_def["provider"],
                            severity=pattern_def["severity"],
                            source="system environment variables",
                            var_name=var_name,
                            redacted_value=_redact(match.group()),
                        ))
                        break
                except re.error:
                    continue

        return findings

    def _scan_env_files(self, patterns: list[dict]) -> list[Finding]:
        """Scan .env files in common locations."""
        findings: list[Finding] = []

        candidate_paths = [
            Path.cwd() / ".env",
            Path.home() / ".env",
            Path.cwd() / ".env.local",
            Path.cwd() / ".env.production",
            Path.home() / ".env.local",
        ]

        for env_path in candidate_paths:
            if not env_path.exists():
                continue

            try:
                content = env_path.read_text(encoding="utf-8", errors="ignore")
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    for pattern_def in patterns:
                        try:
                            match = re.search(pattern_def["pattern"], line)
                            if match:
                                var_name = line.split("=")[0].strip() if "=" in line else "unknown"
                                findings.append(_build_finding(
                                    module_name=self.name,
                                    provider=pattern_def["provider"],
                                    severity=pattern_def["severity"],
                                    source=str(env_path),
                                    var_name=var_name,
                                    redacted_value=_redact(match.group()),
                                ))
                                break
                        except re.error:
                            continue

            except (PermissionError, OSError):
                continue

        return findings

    def _scan_shell_profiles(self, patterns: list[dict]) -> list[Finding]:
        """Scan shell profile files on Unix/macOS systems."""
        findings: list[Finding] = []

        profile_paths = [
            Path.home() / ".bashrc",
            Path.home() / ".zshrc",
            Path.home() / ".profile",
            Path.home() / ".bash_profile",
        ]

        for profile_path in profile_paths:
            if not profile_path.exists():
                continue

            try:
                content = profile_path.read_text(encoding="utf-8", errors="ignore")
                for line in content.splitlines():
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue

                    for pattern_def in patterns:
                        try:
                            match = re.search(pattern_def["pattern"], line)
                            if match:
                                var_name = line.split("=")[0].replace("export", "").strip()
                                findings.append(_build_finding(
                                    module_name=self.name,
                                    provider=pattern_def["provider"],
                                    severity=pattern_def["severity"],
                                    source=str(profile_path),
                                    var_name=var_name,
                                    redacted_value=_redact(match.group()),
                                ))
                                break
                        except re.error:
                            continue

            except (PermissionError, OSError):
                continue

        return findings

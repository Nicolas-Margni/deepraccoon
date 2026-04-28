"""
PackageScanner: detects Python packages related to AI or LLMs installed
in the current environment, comparing against signatures.json["python_packages"].

Runs 'pip list --format=json' as a subprocess and parses the output.
Falls back to pip3 and direct sys.executable invocation for compatibility.
"""

import json
import subprocess
import sys

from core.finding import Finding
from modules.base_module import BaseModule


def _run_pip_list(pip_cmd: str) -> list[dict] | None:
    """
    Run 'pip list --format=json' and return the package list.

    Args:
        pip_cmd: pip command to use ('pip', 'pip3', etc.)

    Returns:
        List of dicts with 'name' and 'version', or None if the command failed.
    """
    try:
        result = subprocess.run(
            [pip_cmd, "list", "--format=json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return json.loads(result.stdout)
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        pass
    return None


def _get_installed_packages() -> dict[str, str]:
    """
    Get all packages installed in the current Python environment.

    Tries multiple strategies in order of preference:
    1. sys.executable -m pip (always points to the correct Python)
    2. pip directly
    3. pip3 as fallback

    Returns:
        Dictionary of {normalized_name: version}.
    """
    try:
        result = subprocess.run(
            [sys.executable, "-m", "pip", "list", "--format=json"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            packages = json.loads(result.stdout)
            return {pkg["name"].lower(): pkg["version"] for pkg in packages}
    except (subprocess.TimeoutExpired, json.JSONDecodeError, FileNotFoundError):
        pass

    for cmd in ("pip", "pip3"):
        packages = _run_pip_list(cmd)
        if packages is not None:
            return {pkg["name"].lower(): pkg["version"] for pkg in packages}

    return {}


class PackageScanner(BaseModule):
    """
    Detects installed Python AI packages by comparing against signatures.json.

    Each detected package generates a MEDIUM severity Finding with
    the package name and installed version as evidence.
    """

    @property
    def name(self) -> str:
        return "package_scanner"

    @property
    def description(self) -> str:
        return "Detects installed Python AI/LLM packages in the environment"

    def run(self) -> list[Finding]:
        """
        Get the list of installed packages and compare against known signatures.

        Returns:
            List of Finding objects, one per detected AI package.
        """
        findings: list[Finding] = []
        known_packages = self.signatures.get("python_packages", [])
        installed = _get_installed_packages()

        if not installed:
            return findings

        for signature in known_packages:
            pkg_name = signature["name"].lower()
            if pkg_name in installed:
                version = installed[pkg_name]
                findings.append(Finding(
                    module=self.name,
                    severity="MEDIUM",
                    title=f"AI package installed: {signature['name']}",
                    description=(
                        f"{signature['description']} found installed "
                        f"in the current Python environment."
                    ),
                    evidence=f"{signature['name']}=={version}",
                    recommendation=(
                        f"Verify whether '{signature['name']}' is authorized "
                        f"by your organization's policy. If not, remove it with: "
                        f"pip uninstall {signature['name']}"
                    ),
                ))

        return findings

"""
Scanner: main orchestrator for DeepRaccoon.

This is the only file that knows about all detection modules.
To add a new module:
  1. Create the file in modules/
  2. Import it here
  3. Add it to _build_modules()

Nothing else needs to be modified.
"""

import json
import sys
from pathlib import Path

from core.finding import Finding
from core.risk_score import RiskResult, calculate
from modules.base_module import BaseModule
from modules.process_scanner import ProcessScanner
from modules.env_scanner import EnvScanner
from modules.package_scanner import PackageScanner
from modules.network_scanner import NetworkScanner
from modules.config_scanner import ConfigScanner
from modules.browser_scanner import BrowserScanner
from modules.app_scanner import AppScanner


def _load_signatures() -> dict:
    """
    Load config/signatures.json from the project root.

    Returns:
        Dictionary with all known signatures.

    Raises:
        SystemExit: If the file is missing or contains invalid JSON.
    """
    base_dir = Path(__file__).parent.parent
    signatures_path = base_dir / "config" / "signatures.json"

    if not signatures_path.exists():
        print(f"[ERROR] signatures.json not found at: {signatures_path}")
        sys.exit(1)

    try:
        with open(signatures_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except json.JSONDecodeError as e:
        print(f"[ERROR] signatures.json contains invalid JSON: {e}")
        sys.exit(1)


def _build_modules(signatures: dict, scan_mode: str) -> list[BaseModule]:
    """
    Instantiate and return the list of modules to run based on scan mode.

    Args:
        signatures: Signatures dictionary loaded from JSON.
        scan_mode:  'full' runs all modules, 'quick' runs only essential ones.

    Returns:
        List of module instances ready to execute.
    """
    all_modules: list[BaseModule] = [
        ProcessScanner(signatures),   # Stage 2a
        EnvScanner(signatures),       # Stage 2b
        PackageScanner(signatures),   # Stage 2c
        NetworkScanner(signatures),   # Stage 3a
        ConfigScanner(signatures),    # Stage 3b
        BrowserScanner(signatures),    # Stage 5
        AppScanner(signatures),        # Stage 5b
    ]

    if scan_mode == "quick":
        quick_names = {"process_scanner", "env_scanner"}
        return [m for m in all_modules if m.name in quick_names]

    return all_modules


class Scanner:
    """
    Main orchestrator. Loads signatures, instantiates modules and runs them all.

    Usage:
        scanner = Scanner(scan_mode="full")
        findings, risk = scanner.run_all()
    """

    def __init__(self, scan_mode: str = "full") -> None:
        """
        Args:
            scan_mode: 'full' runs all modules, 'quick' runs only essential ones.
        """
        self.scan_mode = scan_mode
        self.signatures = _load_signatures()
        self.modules = _build_modules(self.signatures, scan_mode)

    def run_all(self) -> tuple[list[Finding], RiskResult]:
        """
        Run all configured modules and calculate the final risk score.

        Each module runs independently. If one fails, the error is logged
        and the scan continues without interruption.

        Returns:
            Tuple of (findings, risk_result) with all findings and the score.
        """
        all_findings: list[Finding] = []

        for module in self.modules:
            try:
                findings = module.run()
                all_findings.extend(findings)
            except Exception as e:
                print(f"[WARN] Module '{module.name}' failed unexpectedly: {e}")

        all_findings.sort(key=lambda f: f.severity_order())
        risk_result = calculate(all_findings)

        return all_findings, risk_result

    @property
    def module_count(self) -> int:
        """Return the number of modules that will run."""
        return len(self.modules)

    @property
    def module_names(self) -> list[str]:
        """Return the names of all registered modules."""
        return [m.name for m in self.modules]

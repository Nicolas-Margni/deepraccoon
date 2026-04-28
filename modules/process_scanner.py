"""
ProcessScanner: detects AI tool processes actively running on the system
by comparing against the known signatures list in signatures.json.

Uses psutil to iterate over all active processes in a cross-platform way
(Windows, Linux, macOS).
"""

import psutil

from core.finding import Finding
from modules.base_module import BaseModule


class ProcessScanner(BaseModule):
    """
    Detects active AI processes by comparing against signatures.json["processes"].

    Generates a HIGH severity Finding for each detected process, including
    the PID, executable name and full path as evidence.
    """

    @property
    def name(self) -> str:
        return "process_scanner"

    @property
    def description(self) -> str:
        return "Detects AI tool processes actively running on the system"

    def run(self) -> list[Finding]:
        """
        Iterate over all active processes and compare against known signatures.

        Handles AccessDenied and NoSuchProcess without crashing — it is normal
        for some system processes to be inaccessible without elevated privileges.

        Returns:
            List of Finding objects, one per detected AI process.
        """
        findings: list[Finding] = []
        known_processes = self.signatures.get("processes", [])

        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                proc_name = (proc.info["name"] or "").lower()
                proc_exe  = proc.info["exe"] or ""

                for signature in known_processes:
                    sig_name = signature["name"].lower()

                    if sig_name in proc_name or proc_name in (sig_name, sig_name + ".exe"):
                        evidence = (
                            f"PID {proc.info['pid']} | "
                            f"Name: {proc.info['name']} | "
                            f"Path: {proc_exe or 'unavailable'}"
                        )
                        findings.append(Finding(
                            module=self.name,
                            severity="HIGH",
                            title=f"Active AI process: {signature['name']}",
                            description=(
                                f"{signature['description']} detected running "
                                f"actively on this system."
                            ),
                            evidence=evidence,
                            recommendation=(
                                f"Verify whether '{signature['name']}' is authorized. "
                                f"If not, terminate the process with: "
                                f"taskkill /PID {proc.info['pid']} /F"
                            ),
                        ))
                        break

            except psutil.AccessDenied:
                continue
            except psutil.NoSuchProcess:
                continue

        return findings

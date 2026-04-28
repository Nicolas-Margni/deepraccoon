"""
FileReporter: exports scan reports to timestamped folders.

Each scan generates its own folder inside reports/:
    reports/Scan-001-2026-04-19_20-30-00/
        report.json
        report.txt
"""

import json
from datetime import datetime
from pathlib import Path

from core.finding import Finding
from core.risk_score import RiskResult


def create_scan_folder(base_dir: Path | None = None) -> Path:
    """
    Create and return the output folder for this scan.

    The folder name includes a sequence number and the current
    date/time so reports stay chronologically ordered.

    Args:
        base_dir: Root folder where reports are created.
                  Default: <project root>/reports/

    Returns:
        Path to the created folder, ready for writing files.
    """
    if base_dir is None:
        base_dir = Path(__file__).parent.parent / "reports"

    base_dir.mkdir(parents=True, exist_ok=True)

    existing  = sorted(base_dir.glob("Scan-*"))
    next_num  = len(existing) + 1
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    folder    = base_dir / f"Scan-{next_num:03d}-{timestamp}"
    folder.mkdir(parents=True, exist_ok=True)

    return folder


def _build_report(findings: list[Finding], risk: RiskResult, scan_folder: Path) -> dict:
    """Build the complete report dictionary."""
    return {
        "metadata": {
            "tool":           "DeepRaccoon",
            "version":        "0.1.0",
            "generated_at":   datetime.now().isoformat(),
            "scan_folder":    str(scan_folder),
            "total_findings": len(findings),
        },
        "risk_score": {
            "score":     risk.score,
            "level":     risk.level,
            "breakdown": risk.breakdown,
        },
        "findings": [f.to_dict() for f in findings],
    }


def export_json(findings: list[Finding], risk: RiskResult, scan_folder: Path) -> Path:
    """
    Export the full report to report.json inside the scan folder.

    Args:
        findings:    List of detected findings.
        risk:        Risk calculation result.
        scan_folder: Scan folder created by create_scan_folder().

    Returns:
        Path to the created JSON file.
    """
    report      = _build_report(findings, risk, scan_folder)
    output_path = scan_folder / "report.json"

    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    return output_path


def export_txt(findings: list[Finding], risk: RiskResult, scan_folder: Path) -> Path:
    """
    Export the full report to report.txt inside the scan folder.

    Args:
        findings:    List of detected findings.
        risk:        Risk calculation result.
        scan_folder: Scan folder created by create_scan_folder().

    Returns:
        Path to the created TXT file.
    """
    output_path = scan_folder / "report.txt"

    lines = [
        "=" * 60,
        "DeepRaccoon — Shadow AI Detection Report",
        f"Generated : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
        f"Folder    : {scan_folder.name}",
        "=" * 60,
        "",
        f"RISK SCORE: {risk.score}/100 — {risk.level}",
        "",
        "Breakdown by severity:",
    ]

    for sev, count in risk.breakdown.items():
        lines.append(f"  {sev:<10} {count}")

    lines += ["", "-" * 60, f"FINDINGS ({len(findings)} total)", "-" * 60, ""]

    if not findings:
        lines.append("No findings detected.")
    else:
        for i, f in enumerate(findings, 1):
            lines += [
                f"[{i}] {f.severity} — {f.title}",
                f"    Module:         {f.module}",
                f"    Description:    {f.description}",
                f"    Evidence:       {f.evidence}",
                f"    Recommendation: {f.recommendation}",
                f"    Timestamp:      {f.timestamp}",
                "",
            ]

    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))

    return output_path

"""
TUI (Terminal User Interface) for DeepRaccoon.

Full-screen interactive menu system. The terminal clears completely
when navigating between screens — only the current screen is visible.

Navigation:
    - Type a number and press Enter to select an option
    - Press 0 or Enter on empty input to go back / exit
"""

import os
import sys
import shutil
from datetime import datetime
from pathlib import Path
from typing import Optional

from blessed import Terminal

from core.finding import Finding
from core.risk_score import RiskResult

term = Terminal()


# ---------------------------------------------------------------------------
# Screen primitives
# ---------------------------------------------------------------------------

def clear() -> None:
    """Clear the entire terminal screen — works on Windows PowerShell and CMD."""
    import subprocess
    if sys.platform == "win32":
        subprocess.run("cls", shell=True)
    else:
        subprocess.run("clear", shell=True)
    # Also send the ANSI clear sequence as a fallback
    print(term.clear, end="", flush=True)


def move(y: int, x: int) -> None:
    """Move cursor to (row y, col x)."""
    print(term.move(y, x), end="", flush=True)


def width() -> int:
    """Current terminal width in columns."""
    return shutil.get_terminal_size((100, 40)).columns


def height() -> int:
    """Current terminal height in rows."""
    return shutil.get_terminal_size((100, 40)).lines


def center(text: str, fill: str = " ") -> str:
    """Center a plain string within the terminal width."""
    w = width()
    stripped = _strip_ansi(text)
    pad = max(0, (w - len(stripped)) // 2)
    return fill * pad + text


def _strip_ansi(text: str) -> str:
    """Remove ANSI escape codes for length calculation."""
    import re
    return re.sub(r'\x1b\[[0-9;]*m', '', text)


def hline(char: str = "─") -> str:
    """Return a horizontal line across the terminal."""
    return char * width()


# ---------------------------------------------------------------------------
# Color helpers
# ---------------------------------------------------------------------------

def cyan(text: str) -> str:
    return term.cyan + text + term.normal


def bold_cyan(text: str) -> str:
    return term.bold + term.cyan + text + term.normal


def bold_white(text: str) -> str:
    return term.bold + term.white + text + term.normal


def dim(text: str) -> str:
    return term.dim + text + term.normal


def green(text: str) -> str:
    return term.bold + term.green + text + term.normal


def yellow(text: str) -> str:
    return term.bold + term.yellow + text + term.normal


def red(text: str) -> str:
    return term.bold + term.red + text + term.normal


def orange(text: str) -> str:
    return term.bold + term.color(214) + text + term.normal


def severity_color(sev: str) -> str:
    colors = {
        "CRITICAL": term.bold + term.red,
        "HIGH":     term.red,
        "MEDIUM":   term.bold + term.yellow,
        "LOW":      term.cyan,
        "INFO":     term.dim,
    }
    return colors.get(sev, "") + sev + term.normal


def risk_color(level: str, text: str) -> str:
    colors = {
        "CRÍTICO":  term.bold + term.red,
        "CRITICAL": term.bold + term.red,
        "ALTO":     term.bold + term.color(214),
        "HIGH":     term.bold + term.color(214),
        "MEDIO":    term.bold + term.yellow,
        "MEDIUM":   term.bold + term.yellow,
        "BAJO":     term.bold + term.green,
        "LOW":      term.bold + term.green,
    }
    return colors.get(level, "") + text + term.normal


# ---------------------------------------------------------------------------
# ASCII Banner
# ---------------------------------------------------------------------------

BANNER_LINES = [
    r"    ██████╗ ███████╗███████╗██████╗ ",
    r"    ██╔══██╗██╔════╝██╔════╝██╔══██╗",
    r"    ██║  ██║█████╗  █████╗  ██████╔╝",
    r"    ██║  ██║██╔══╝  ██╔══╝  ██╔═══╝ ",
    r"    ██████╔╝███████╗███████╗██║     ",
    r"    ╚═════╝ ╚══════╝╚══════╝╚═╝     ",
    r"    ██████╗  █████╗  ██████╗ ██████╗ ██████╗  ██████╗  ██████╗ ███╗   ██╗",
    r"    ██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔═══██╗██╔═══██╗████╗  ██║",
    r"    ██████╔╝███████║██║     ██║     ██║   ██║██║   ██║██║   ██║██╔██╗ ██║",
    r"    ██╔══██╗██╔══██║██║     ██║     ██║   ██║██║   ██║██║   ██║██║╚██╗██║",
    r"    ██║  ██║██║  ██║╚██████╗╚██████╗╚██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║",
    r"    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝  ╚═════╝╚═╝  ╚═══╝",
]


def print_banner(subtitle: str = "") -> None:
    """Print the DeepRaccoon ASCII banner."""
    for line in BANNER_LINES:
        print(bold_cyan(line))
    print()
    if subtitle:
        print(center(dim(subtitle)))
    else:
        admin = _is_admin()
        tag = green("⚡ ADMINISTRATOR") if admin else yellow("⚠  Run as Administrator for full scan")
        print(center(dim("v0.1.0  |  Shadow AI & Unauthorized Tool Detector  |  ") + tag))
    print()
    print(dim(hline()))
    print()


def _is_admin() -> bool:
    """Check administrator / root privileges."""
    try:
        if sys.platform == "win32":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        return os.geteuid() == 0
    except AttributeError:
        return False


# ---------------------------------------------------------------------------
# Input helper
# ---------------------------------------------------------------------------

def prompt(label: str = "Select option") -> str:
    """Display a prompt and return stripped user input."""
    print()
    try:
        return input(f"  {bold_white('›')} {label}: ").strip()
    except (EOFError, KeyboardInterrupt):
        return "0"


def confirm(question: str) -> bool:
    """Ask a y/n question. Returns True for 'y'."""
    try:
        answer = input(f"\n  {bold_white('›')} {question} (y/n): ").strip().lower()
        return answer == "y"
    except (EOFError, KeyboardInterrupt):
        return False


def press_any_key() -> None:
    """Pause until the user presses Enter."""
    try:
        input(f"\n  {dim('Press Enter to continue...')}")
    except (EOFError, KeyboardInterrupt):
        pass


def invalid_option() -> None:
    """Show invalid option message briefly."""
    print(f"\n  {yellow('⚠  Invalid option. Try again.')}")
    press_any_key()


# ---------------------------------------------------------------------------
# Main Menu
# ---------------------------------------------------------------------------

def main_menu() -> None:
    """Main menu loop. Entry point for the TUI."""
    while True:
        clear()
        print_banner()

        print(center(bold_white("MAIN MENU")))
        print()
        print(f"  {cyan('[1]')}  Scan")
        print(f"  {cyan('[2]')}  Reports")
        print(f"  {cyan('[5]')}  Help")
        print(f"  {cyan('[0]')}  Exit")
        print()
        print(dim(hline()))

        choice = prompt()

        if choice == "1":
            scan_menu()
        elif choice == "2":
            reports_menu()
        elif choice == "5":
            help_screen()
        elif choice == "0" or choice == "":
            clear()
            print(center(bold_cyan("Goodbye.")))
            print()
            sys.exit(0)
        else:
            invalid_option()


# ---------------------------------------------------------------------------
# Scan Menu
# ---------------------------------------------------------------------------

def scan_menu() -> None:
    """Scan type selection menu."""
    while True:
        clear()
        print_banner(subtitle="v0.1.0  |  Scan Configuration")
        print(center(bold_white("SELECT SCAN TYPE")))
        print()
        print(f"  {cyan('[1]')}  Full Scan              {dim('— all modules')}")
        print(f"  {cyan('[2]')}  Quick Scan             {dim('— process + environment only')}")
        print(f"  {cyan('[3]')}  Full Scan — Critical   {dim('— all modules, show CRITICAL only')}")
        print(f"  {cyan('[4]')}  Full Scan — Export     {dim('— all modules, save JSON + TXT report')}")
        print()
        print(f"  {cyan('[0]')}  Back")
        print()
        print(dim(hline()))

        choice = prompt()

        if choice == "1":
            run_scan(scan_mode="full", severity_filter="all", auto_export=False)
        elif choice == "2":
            run_scan(scan_mode="quick", severity_filter="all", auto_export=False)
        elif choice == "3":
            run_scan(scan_mode="full", severity_filter="critical", auto_export=False)
        elif choice == "4":
            run_scan(scan_mode="full", severity_filter="all", auto_export=True)
        elif choice == "0" or choice == "":
            return
        else:
            invalid_option()


# ---------------------------------------------------------------------------
# Scan Execution
# ---------------------------------------------------------------------------

def run_scan(scan_mode: str, severity_filter: str, auto_export: bool) -> None:
    """
    Execute a scan with live progress display.

    Args:
        scan_mode:       'full' or 'quick'
        severity_filter: 'all', 'critical', 'high', 'medium', 'low'
        auto_export:     If True, automatically save report after scan
    """
    from core.scanner import Scanner
    from core.finding import SEVERITY_ORDER
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
    from rich.console import Console

    clear()
    print_banner(subtitle="v0.1.0  |  Scanning in progress...")
    print(center(bold_white(f"RUNNING {scan_mode.upper()} SCAN")))
    print()

    scanner = Scanner(scan_mode=scan_mode)

    rich_console = Console()
    all_findings: list[Finding] = []

    with Progress(
        SpinnerColumn(spinner_name="dots", style="cyan"),
        TextColumn("[bold cyan]{task.description}[/bold cyan]"),
        BarColumn(bar_width=30, style="cyan", complete_style="green"),
        TaskProgressColumn(),
        console=rich_console,
        transient=False,
    ) as progress:
        task = progress.add_task("Starting...", total=len(scanner.modules))
        for module in scanner.modules:
            progress.update(task, description=f"Scanning  [{module.name}]")
            try:
                findings = module.run()
                all_findings.extend(findings)
            except Exception as e:
                rich_console.print(f"[yellow]⚠[/yellow] Module '{module.name}' failed: {e}")
            finally:
                progress.advance(task)
        progress.update(task, description="[green]Scan complete[/green]")

    from core.risk_score import calculate
    all_findings.sort(key=lambda f: f.severity_order())
    risk = calculate(all_findings)

    # Apply severity filter
    if severity_filter != "all":
        order_map = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        min_order = order_map.get(severity_filter, 4)
        filtered = [f for f in all_findings if SEVERITY_ORDER.get(f.severity, 99) <= min_order]
    else:
        filtered = all_findings

    # Show results
    _print_scan_results(filtered, risk, scanner.module_names)

    # Auto-export or ask to save
    if auto_export:
        _save_report(filtered, risk)
    else:
        if confirm("Save this report to file?"):
            _save_report(filtered, risk)

    press_any_key()


def _print_scan_results(findings: list[Finding], risk: RiskResult, modules_run: list[str]) -> None:
    """Print scan results in a clean full-screen format."""
    print()
    print(dim(hline()))
    print()
    print(center(bold_white(f"FINDINGS  ({len(findings)} total)")))
    print()

    if not findings:
        print(center(green("✓  No findings detected.")))
    else:
        # Column widths
        col_sev  = 10
        col_title = 30
        col_mod  = 18
        col_ev   = width() - col_sev - col_title - col_mod - 10

        header = (
            f"  {'SEVERITY':<{col_sev}}"
            f"{'TITLE':<{col_title}}"
            f"{'MODULE':<{col_mod}}"
            f"{'EVIDENCE':<{col_ev}}"
        )
        print(bold_white(header))
        print(dim(hline("─")))

        for f in findings:
            sev_display = severity_color(f.severity)
            title = f.title[:col_title - 2] if len(f.title) > col_title - 2 else f.title
            module = f.module[:col_mod - 2] if len(f.module) > col_mod - 2 else f.module
            evidence = f.evidence[:col_ev - 2] if len(f.evidence) > col_ev - 2 else f.evidence

            sev_pad = col_sev - len(f.severity)
            print(
                f"  {sev_display}{' ' * sev_pad}"
                f"{title:<{col_title}}"
                f"{dim(module):<{col_mod + len(dim(''))}}"
                f"{evidence}"
            )

    print()
    print(dim(hline()))
    print()

    # Risk score
    score_text = risk_color(risk.level, f"Risk Score: {risk.score}/100  →  {risk.level}")
    print(f"  {score_text}")
    print()

    breakdown_parts = []
    for sev, count in risk.breakdown.items():
        if count > 0:
            breakdown_parts.append(f"{severity_color(sev)}: {count}")
    if breakdown_parts:
        print(f"  {'  '.join(breakdown_parts)}")

    print()
    print(dim(hline()))


def _save_report(findings: list[Finding], risk: RiskResult) -> None:
    """Save report to a timestamped folder in reports/."""
    from output.file_reporter import create_scan_folder, export_json, export_txt

    scan_folder = create_scan_folder()
    export_json(findings, risk, scan_folder)
    export_txt(findings, risk, scan_folder)
    print(f"\n  {green('✓')}  Report saved to: {bold_white(str(scan_folder))}")


# ---------------------------------------------------------------------------
# Reports Menu
# ---------------------------------------------------------------------------

def _get_reports() -> list[Path]:
    """Return sorted list of scan folders in reports/, newest first."""
    reports_dir = Path(__file__).parent.parent / "reports"
    if not reports_dir.exists():
        return []
    folders = sorted(
        [f for f in reports_dir.iterdir() if f.is_dir() and f.name.startswith("Scan-")],
        reverse=True,
    )
    return folders


def reports_menu() -> None:
    """Reports management menu."""
    while True:
        clear()
        print_banner(subtitle="v0.1.0  |  Reports")
        print(center(bold_white("REPORTS")))
        print()
        print(f"  {cyan('[1]')}  View last report")
        print(f"  {cyan('[2]')}  View any report")
        print(f"  {cyan('[3]')}  Export report to another format")
        print(f"  {cyan('[4]')}  Delete last report")
        print(f"  {cyan('[5]')}  Delete any report")
        print()
        print(f"  {cyan('[0]')}  Back")
        print()
        print(dim(hline()))

        choice = prompt()

        if choice == "1":
            _view_last_report()
        elif choice == "2":
            _pick_report(action="view")
        elif choice == "3":
            _pick_report(action="export")
        elif choice == "4":
            _delete_last_report()
        elif choice == "5":
            _pick_report(action="delete")
        elif choice == "0" or choice == "":
            return
        else:
            invalid_option()


def _print_report_list(reports: list[Path]) -> None:
    """Print a numbered list of available reports."""
    print(bold_white(f"  {'#':<5}{'Report':<45}{'Files'}"))
    print(dim(hline("─")))
    for i, folder in enumerate(reports, 1):
        files = []
        if (folder / "report.json").exists():
            files.append("JSON")
        if (folder / "report.txt").exists():
            files.append("TXT")
        file_str = " + ".join(files) if files else "empty"
        print(f"  {cyan(str(i)):<5}{folder.name:<45}{dim(file_str)}")
    print()


def _view_last_report() -> None:
    """Display the most recent report."""
    reports = _get_reports()
    if not reports:
        clear()
        print_banner()
        print(center(yellow("No reports found. Run a scan first.")))
        press_any_key()
        return
    _display_report(reports[0])


def _pick_report(action: str) -> None:
    """
    Show list of reports and let the user pick one by number.

    Args:
        action: 'view', 'export', or 'delete'
    """
    action_labels = {
        "view":   "VIEW REPORT",
        "export": "EXPORT REPORT",
        "delete": "DELETE REPORT",
    }

    reports = _get_reports()
    if not reports:
        clear()
        print_banner()
        print(center(yellow("No reports found. Run a scan first.")))
        press_any_key()
        return

    while True:
        clear()
        print_banner(subtitle=f"v0.1.0  |  {action_labels.get(action, 'REPORTS')}")
        print(center(bold_white(action_labels.get(action, "SELECT REPORT"))))
        print()
        _print_report_list(reports)
        print(f"  {cyan('[0]')}  Back")
        print()
        print(dim(hline()))

        choice = prompt("Select report number")

        if choice == "0" or choice == "":
            return

        try:
            index = int(choice) - 1
            if index < 0 or index >= len(reports):
                raise ValueError
        except ValueError:
            invalid_option()
            continue

        selected = reports[index]

        if action == "view":
            _display_report(selected)
            return
        elif action == "export":
            _export_report(selected)
            return
        elif action == "delete":
            _confirm_delete(selected)
            reports = _get_reports()  # Refresh list
            if not reports:
                return


def _display_report(folder: Path) -> None:
    """Render a saved report to the screen."""
    import json

    clear()
    print_banner(subtitle=f"v0.1.0  |  {folder.name}")
    print(center(bold_white("REPORT VIEWER")))
    print()

    json_file = folder / "report.json"
    txt_file  = folder / "report.txt"

    if json_file.exists():
        try:
            data = json.loads(json_file.read_text(encoding="utf-8"))
            findings_data = data.get("findings", [])
            risk_data     = data.get("risk_score", {})
            metadata      = data.get("metadata", {})

            print(f"  {dim('Scan date:')}  {metadata.get('generated_at', 'unknown')[:19].replace('T', ' ')}")
            print(f"  {dim('Total findings:')}  {bold_white(str(metadata.get('total_findings', 0)))}")
            print()
            print(dim(hline("─")))
            print()

            if not findings_data:
                print(center(green("✓  No findings in this report.")))
            else:
                col_sev   = 10
                col_title = 32
                col_ev    = width() - col_sev - col_title - 6

                print(bold_white(f"  {'SEVERITY':<{col_sev}}{'TITLE':<{col_title}}{'EVIDENCE'}"))
                print(dim(hline("─")))

                for f in findings_data:
                    sev   = f.get("severity", "INFO")
                    title = f.get("title", "")[:col_title - 2]
                    ev    = f.get("evidence", "")[:col_ev - 2]
                    sev_display = severity_color(sev)
                    sev_pad = col_sev - len(sev)
                    print(f"  {sev_display}{' ' * sev_pad}{title:<{col_title}}{dim(ev)}")

            print()
            print(dim(hline()))
            score = risk_data.get("score", 0)
            level = risk_data.get("level", "LOW")
            print(f"\n  {risk_color(level, f'Risk Score: {score}/100  →  {level}')}")
            print()

        except (json.JSONDecodeError, KeyError):
            if txt_file.exists():
                print(txt_file.read_text(encoding="utf-8"))
            else:
                print(yellow("  Could not read report file."))

    elif txt_file.exists():
        print(txt_file.read_text(encoding="utf-8"))
    else:
        print(yellow("  No readable report files found in this folder."))

    print(dim(hline()))
    press_any_key()


def _export_report(folder: Path) -> None:
    """Export an existing report to another format."""
    import json

    clear()
    print_banner(subtitle="v0.1.0  |  Export Report")
    print(center(bold_white("EXPORT REPORT")))
    print()
    print(f"  Selected: {bold_white(folder.name)}")
    print()
    print(f"  {cyan('[1]')}  Export as JSON")
    print(f"  {cyan('[2]')}  Export as TXT")
    print(f"  {cyan('[3]')}  Export both")
    print()
    print(f"  {cyan('[0]')}  Back")
    print()
    print(dim(hline()))

    choice = prompt()

    if choice == "0" or choice == "":
        return

    json_file = folder / "report.json"
    if not json_file.exists():
        print(yellow("\n  Cannot export: report.json not found in this scan folder."))
        press_any_key()
        return

    try:
        data      = json.loads(json_file.read_text(encoding="utf-8"))
        findings  = [_dict_to_finding(f) for f in data.get("findings", [])]
        risk      = _dict_to_risk(data.get("risk_score", {}))
    except (json.JSONDecodeError, KeyError) as e:
        print(yellow(f"\n  Could not read report data: {e}"))
        press_any_key()
        return

    from output.file_reporter import export_json, export_txt

    if choice in ("1", "3"):
        export_json(findings, risk, folder)
        print(f"\n  {green('✓')}  JSON exported to: {folder / 'report.json'}")

    if choice in ("2", "3"):
        export_txt(findings, risk, folder)
        print(f"\n  {green('✓')}  TXT exported to: {folder / 'report.txt'}")

    press_any_key()


def _delete_last_report() -> None:
    """Delete the most recent report after confirmation."""
    reports = _get_reports()
    if not reports:
        clear()
        print_banner()
        print(center(yellow("No reports found.")))
        press_any_key()
        return
    _confirm_delete(reports[0])


def _confirm_delete(folder: Path) -> None:
    """Ask confirmation and delete a report folder."""
    clear()
    print_banner(subtitle="v0.1.0  |  Delete Report")
    print(center(red("⚠  DELETE REPORT")))
    print()
    print(f"  Report: {bold_white(folder.name)}")
    print()

    if confirm(f"Delete '{folder.name}'? This cannot be undone"):
        try:
            shutil.rmtree(folder)
            print(f"\n  {green('✓')}  Report deleted.")
        except OSError as e:
            print(f"\n  {red('✗')}  Could not delete: {e}")
    else:
        print(f"\n  {dim('Deletion cancelled.')}")

    press_any_key()


# ---------------------------------------------------------------------------
# Helper: reconstruct objects from saved JSON data
# ---------------------------------------------------------------------------

def _dict_to_finding(data: dict) -> Finding:
    """Reconstruct a Finding from a saved dict."""
    return Finding(
        module=data.get("module", "unknown"),
        severity=data.get("severity", "INFO"),
        title=data.get("title", ""),
        description=data.get("description", ""),
        evidence=data.get("evidence", ""),
        recommendation=data.get("recommendation", ""),
        timestamp=data.get("timestamp", datetime.now().isoformat()),
    )


def _dict_to_risk(data: dict) -> RiskResult:
    """Reconstruct a RiskResult from a saved dict."""
    from core.risk_score import RiskResult
    return RiskResult(
        score=data.get("score", 0),
        level=data.get("level", "LOW"),
        color=data.get("color", "green"),
        breakdown=data.get("breakdown", {}),
    )


# ---------------------------------------------------------------------------
# Help Screen
# ---------------------------------------------------------------------------

def help_screen() -> None:
    """Display help and module information."""
    clear()
    print_banner(subtitle="v0.1.0  |  Help")
    print(center(bold_white("HELP & MODULE REFERENCE")))
    print()

    modules = [
        ("process_scanner",  "Detects AI processes actively running (Ollama, LM Studio...)",      "Active",  "HIGH"),
        ("env_scanner",      "Detects AI API keys in environment variables and .env files",        "Active",  "CRITICAL"),
        ("package_scanner",  "Detects installed Python AI/LLM packages (openai, anthropic...)",   "Active",  "MEDIUM"),
        ("network_scanner",  "Detects active connections and DNS cache hits to LLM APIs",          "Active",  "HIGH"),
        ("config_scanner",   "Detects AI tool configuration folders (Claude Desktop, Cursor...)", "Active",  "LOW"),
        ("browser_scanner",  "Detects AI site visits and AI extensions in the browser",            "Active",  "LOW/MED"),
        ("app_scanner",      "Detects AI desktop applications installed on the system",            "Active",  "MEDIUM"),
    ]

    print(bold_white(f"  {'MODULE':<22}{'DETECTS':<52}{'STATUS':<10}{'SEVERITY'}"))
    print(dim(hline("─")))

    for name, description, status, sev in modules:
        status_str = green(status) if status == "Active" else yellow(status)
        print(f"  {cyan(name):<22}{description:<52}{status_str:<10}{dim(sev)}")

    print()
    print(dim(hline()))
    print()
    print(bold_white("  SEVERITY SCALE"))
    print()
    print(f"  {severity_color('CRITICAL')}  API keys exposed — immediate action required")
    print(f"  {severity_color('HIGH')}      Active AI process or browser extension with system access")
    print(f"  {severity_color('MEDIUM')}    AI app installed or developer API console visited")
    print(f"  {severity_color('LOW')}       AI chat site visited or config folder found")
    print(f"  {severity_color('INFO')}      Informational — no action required")
    print()
    print(dim(hline()))
    print()
    print(bold_white("  RISK SCORE"))
    print()
    print(f"  {risk_color('CRÍTICO', '80–100  CRITICAL')}   — Immediate investigation required")
    print(f"  {risk_color('ALTO',    '60–79   HIGH')}       — Significant AI presence detected")
    print(f"  {risk_color('MEDIO',   '40–59   MEDIUM')}     — Moderate AI usage found")
    print(f"  {risk_color('BAJO',    '0–39    LOW')}        — Minimal or no AI presence")
    print()
    print(dim(hline()))

    press_any_key()

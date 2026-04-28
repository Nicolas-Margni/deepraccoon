"""
TerminalReporter: formatted terminal output using rich.

Handles the DeepRaccoon banner, command menu, findings table,
progress bar during scanning, and risk score display.
"""

import ctypes
import os
import sys

from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich import box

from core.finding import Finding
from core.risk_score import RiskResult


SEVERITY_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "red",
    "MEDIUM":   "yellow",
    "LOW":      "cyan",
    "INFO":     "dim",
}

RISK_LEVEL_COLORS = {
    "CRITICAL": "bold red",
    "HIGH":     "bold orange3",
    "MEDIUM":   "bold yellow",
    "LOW":      "bold green",
}

ASCII_BANNER = r"""
    ██████╗ ███████╗███████╗██████╗ 
    ██╔══██╗██╔════╝██╔════╝██╔══██╗
    ██║  ██║█████╗  █████╗  ██████╔╝
    ██║  ██║██╔══╝  ██╔══╝  ██╔═══╝ 
    ██████╔╝███████╗███████╗██║     
    ╚═════╝ ╚══════╝╚══════╝╚═╝     
    ██████╗  █████╗  ██████╗ ██████╗ ██████╗  ██████╗  ██████╗ ███╗   ██╗
    ██╔══██╗██╔══██╗██╔════╝██╔════╝██╔═══██╗██╔═══██╗██╔═══██╗████╗  ██║
    ██████╔╝███████║██║     ██║     ██║   ██║██║   ██║██║   ██║██╔██╗ ██║
    ██╔══██╗██╔══██║██║     ██║     ██║   ██║██║   ██║██║   ██║██║╚██╗██║
    ██║  ██║██║  ██║╚██████╗╚██████╗╚██████╔╝╚██████╔╝╚██████╔╝██║ ╚████║
    ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝ ╚═════╝ ╚═════╝  ╚═════╝  ╚═════╝╚═╝  ╚═══╝
"""

console = Console()


def _is_admin() -> bool:
    """Check if the process is running with administrator/root privileges."""
    try:
        if sys.platform == "win32":
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except AttributeError:
        return False


def print_banner() -> None:
    """Print the DeepRaccoon ASCII banner with version and admin status."""
    console.print(f"[bold cyan]{ASCII_BANNER}[/bold cyan]")

    version_text = Text()
    version_text.append("  v0.1.0", style="dim")
    version_text.append("  |  ", style="dim")
    version_text.append("Shadow AI & Unauthorized Tool Detector", style="bold white")

    if _is_admin():
        version_text.append("  |  ", style="dim")
        version_text.append("⚡ ADMINISTRATOR", style="bold green")
    else:
        version_text.append("  |  ", style="dim")
        version_text.append("⚠  Limited privileges — run as Administrator for full scan", style="bold yellow")

    console.print(version_text)
    console.print()


def print_menu() -> None:
    """Print the interactive command menu shown when DeepRaccoon is launched without arguments."""
    console.print(Panel(
        "[bold white]AVAILABLE COMMANDS[/bold white]",
        border_style="cyan",
        padding=(0, 2),
    ))
    console.print()

    scan_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    scan_table.add_column("Command", style="bold cyan", width=52)
    scan_table.add_column("Description", style="white")

    scan_table.add_row("python main.py --scan full",                    "Run all detection modules")
    scan_table.add_row("python main.py --scan quick",                   "Run only process + environment scanner")
    scan_table.add_row("python main.py --scan full --output json",      "Save JSON report to reports/ folder")
    scan_table.add_row("python main.py --scan full --output txt",       "Save TXT report to reports/ folder")
    scan_table.add_row("python main.py --scan full --output both",      "Save JSON + TXT report to reports/ folder")

    console.print(Panel(scan_table, title="[bold]Scanning[/bold]", border_style="dim", padding=(0, 1)))
    console.print()

    filter_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    filter_table.add_column("Command", style="bold cyan", width=52)
    filter_table.add_column("Description", style="white")

    filter_table.add_row("python main.py --scan full --severity critical", "Show only CRITICAL findings")
    filter_table.add_row("python main.py --scan full --severity high",     "Show CRITICAL and HIGH findings")
    filter_table.add_row("python main.py --scan full --quiet",             "Suppress banner, show report only")

    console.print(Panel(filter_table, title="[bold]Filtering & Output[/bold]", border_style="dim", padding=(0, 1)))
    console.print()

    modules_table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    modules_table.add_column("Module",          style="bold cyan", width=22)
    modules_table.add_column("What it detects", style="white",     width=42)
    modules_table.add_column("Status",          style="dim",       width=10)

    modules_table.add_row("process_scanner", "Active AI processes (Ollama, LM Studio, Jan...)",  "[green]Active[/green]")
    modules_table.add_row("env_scanner",     "API keys in environment variables and .env files", "[green]Active[/green]")
    modules_table.add_row("package_scanner", "Installed Python AI/LLM packages",                 "[green]Active[/green]")
    modules_table.add_row("network_scanner", "Active connections to LLM APIs",                   "[green]Active[/green]")
    modules_table.add_row("config_scanner",  "AI tool config folders and files",                  "[green]Active[/green]")
    modules_table.add_row("browser_scanner", "Browser history, cookies and AI extensions",        "[green]Active[/green]")
    modules_table.add_row("app_scanner",     "AI desktop applications installed on the system",    "[green]Active[/green]")

    console.print(Panel(modules_table, title="[bold]Detection Modules[/bold]", border_style="dim", padding=(0, 1)))
    console.print()
    console.print("[dim]  Tip: run as Administrator for unrestricted access to all system processes.[/dim]")
    console.print()


def print_scan_start(scan_mode: str, module_count: int) -> None:
    """Print scan start information."""
    console.print(
        f"[dim]Mode:[/dim] [bold]{scan_mode.upper()}[/bold]  "
        f"[dim]Active modules:[/dim] [bold]{module_count}[/bold]\n"
    )


def run_scan_with_progress(scanner) -> tuple[list[Finding], "RiskResult"]:
    """
    Run all scanner modules with a live progress bar.

    Shows a spinner + module name while each module runs, so the user
    always knows the tool is working and which module is currently active.

    Args:
        scanner: Initialized Scanner instance.

    Returns:
        Tuple of (findings, risk_result).
    """
    from core.risk_score import calculate

    all_findings: list[Finding] = []

    with Progress(
        SpinnerColumn(spinner_name="dots", style="cyan"),
        TextColumn("[bold cyan]{task.description}[/bold cyan]"),
        BarColumn(bar_width=30, style="cyan", complete_style="green"),
        TaskProgressColumn(),
        console=console,
        transient=False,
    ) as progress:

        task = progress.add_task(
            "Starting scan...",
            total=len(scanner.modules),
        )

        for module in scanner.modules:
            progress.update(task, description=f"Scanning  [{module.name}]")
            try:
                findings = module.run()
                all_findings.extend(findings)
            except Exception as e:
                console.print(f"[yellow]⚠[/yellow] Module '{module.name}' failed: {e}")
            finally:
                progress.advance(task)

        progress.update(task, description="[green]Scan complete[/green]")

    all_findings.sort(key=lambda f: f.severity_order())
    risk_result = calculate(all_findings)
    return all_findings, risk_result


def print_findings(findings: list[Finding]) -> None:
    """Print findings table grouped by severity. Shows clean message if empty."""
    if not findings:
        console.print("\n[bold green]✓[/bold green] No findings detected.\n")
        return

    table = Table(
        box=box.ROUNDED,
        show_header=True,
        header_style="bold white",
        border_style="dim",
        title=f"[bold]Findings[/bold] ({len(findings)} total)",
        title_style="bold white",
    )

    table.add_column("Severity", style="bold", width=10)
    table.add_column("Title",    width=30)
    table.add_column("Module",   style="dim", width=16)
    table.add_column("Evidence", width=40)

    for finding in findings:
        color = SEVERITY_COLORS.get(finding.severity, "white")
        table.add_row(
            Text(finding.severity, style=color),
            finding.title,
            finding.module,
            finding.evidence,
        )

    console.print(table)


def print_risk_score(risk: RiskResult) -> None:
    """Print the final risk score with color and severity breakdown."""
    level_style = RISK_LEVEL_COLORS.get(risk.level, "white")

    score_text = Text()
    score_text.append("Risk Score: ", style="bold")
    score_text.append(f"{risk.score}/100", style=level_style)
    score_text.append("  →  ", style="dim")
    score_text.append(risk.level, style=level_style)

    breakdown_parts = []
    for sev, count in risk.breakdown.items():
        if count > 0:
            color = SEVERITY_COLORS.get(sev, "white")
            breakdown_parts.append(f"[{color}]{sev}: {count}[/{color}]")

    breakdown_str = "  ".join(breakdown_parts) if breakdown_parts else "[dim]no findings[/dim]"

    console.print(Panel(
        f"{score_text}\n{breakdown_str}",
        title="[bold]Final Result[/bold]",
        border_style="dim",
        padding=(0, 2),
    ))


def print_summary(findings: list[Finding], risk: RiskResult, modules_run: list[str]) -> None:
    """Print the complete final summary: findings table and risk score."""
    print_findings(findings)
    print_risk_score(risk)

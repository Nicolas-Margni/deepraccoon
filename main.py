"""
DeepRaccoon — entry point.

Shadow AI & Unauthorized Tool Detector

Simply run:
    python main.py

The interactive TUI menu will launch automatically.
Legacy CLI flags are still supported for scripting:
    python main.py --scan full
    python main.py --scan full --output both --quiet
"""

import argparse
import sys


def _run_tui() -> None:
    """Launch the full-screen interactive TUI."""
    from output.tui import main_menu
    main_menu()


def _run_cli(args: argparse.Namespace) -> int:
    """
    Legacy CLI mode — runs without the interactive TUI.
    Useful for scripting, automation, or CI pipelines.
    """
    from core.scanner import Scanner
    from core.finding import SEVERITY_ORDER
    from output.terminal_reporter import (
        print_banner,
        print_summary,
        run_scan_with_progress,
        console,
    )
    from output.file_reporter import create_scan_folder, export_json, export_txt
    from pathlib import Path

    if not args.quiet:
        print_banner()

    scanner = Scanner(scan_mode=args.scan)

    if not args.quiet:
        console.print(
            f"[dim]Mode:[/dim] [bold]{args.scan.upper()}[/bold]  "
            f"[dim]Modules:[/dim] [bold]{', '.join(scanner.module_names)}[/bold]\n"
        )

    if args.quiet:
        findings, risk = scanner.run_all()
    else:
        findings, risk = run_scan_with_progress(scanner)

    # Severity filter
    if args.severity != "all":
        order_map = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        min_order = order_map.get(args.severity, 4)
        findings = [f for f in findings if SEVERITY_ORDER.get(f.severity, 99) <= min_order]

    console.print()

    if args.output == "terminal":
        print_summary(findings, risk, scanner.module_names)
    else:
        reports_dir = Path(args.reports_dir) if args.reports_dir else None
        scan_folder = create_scan_folder(reports_dir)

        if args.output in ("json", "both"):
            p = export_json(findings, risk, scan_folder)
            if not args.quiet:
                console.print(f"[green]✓[/green] JSON saved: [bold]{p}[/bold]")

        if args.output in ("txt", "both"):
            p = export_txt(findings, risk, scan_folder)
            if not args.quiet:
                console.print(f"[green]✓[/green] TXT saved:  [bold]{p}[/bold]")

        print_summary(findings, risk, scanner.module_names)

    return 0


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="deepraccoon",
        description="DeepRaccoon — Shadow AI & Unauthorized Tool Detector",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Without arguments, launches the interactive TUI menu.

CLI examples (for scripting):
  python main.py --scan full
  python main.py --scan full --output both
  python main.py --scan full --severity critical --quiet
        """,
    )
    parser.add_argument("--scan",        choices=["full", "quick"],                          default=None)
    parser.add_argument("--output",      choices=["terminal", "json", "txt", "both"],        default="terminal")
    parser.add_argument("--severity",    choices=["all", "critical", "high", "medium", "low"], default="all")
    parser.add_argument("--quiet",       action="store_true", default=False)
    parser.add_argument("--reports-dir", default=None, metavar="PATH")
    return parser


def main() -> int:
    parser = _build_parser()
    args = parser.parse_args()

    # No --scan flag → launch TUI
    if args.scan is None:
        _run_tui()
        return 0

    # --scan flag present → legacy CLI mode
    return _run_cli(args)


if __name__ == "__main__":
    sys.exit(main())

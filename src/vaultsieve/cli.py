from __future__ import annotations

import argparse
from pathlib import Path

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from vaultsieve import __version__
from vaultsieve.audit import run_audit
from vaultsieve.cleaner import write_clean_output
from vaultsieve.errors import VaultSieveError
from vaultsieve.models import AuditOptions, InputFormat, Severity
from vaultsieve.reports.html import render_html_report
from vaultsieve.reports.json import render_json_report
from vaultsieve.reports.terminal import print_terminal_report
from vaultsieve.reports.text import render_text_report


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vaultsieve")
    parser.add_argument("--version", action="version", version=f"vaultsieve {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    audit = subparsers.add_parser("audit", help="Audit an exported vault file.")
    audit.add_argument("input_path", type=Path)
    audit.add_argument("--format", choices=["bitwarden", "csv"], required=True)
    audit.add_argument("--check-breaches", action="store_true")
    audit.add_argument("--hibp-workers", type=int, default=4)
    audit.add_argument("--report-dir", type=Path)
    audit.add_argument("--clean-output", type=Path)
    audit.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low"],
        default="low",
    )

    subparsers.add_parser("tui", help="Start the guided terminal interface.")
    return parser


def main(argv: list[str] | None = None) -> int:
    console = Console(stderr=True)
    parser = build_parser()
    try:
        args = parser.parse_args(argv)

        if args.command == "tui":
            from vaultsieve.tui import run_tui

            return run_tui()

        if args.command is None:
            from vaultsieve.tui import run_tui

            return run_tui()

        if args.command == "audit":
            return _run_audit_command(args)

        parser.print_help()
        return 2
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled. Bye.[/yellow]")
        return 130
    except VaultSieveError as err:
        console.print(f"[red]Error:[/red] {err}")
        return 1


def _run_audit_command(args: argparse.Namespace) -> int:
    input_format: InputFormat = args.format
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
    ) as progress:
        task_id = progress.add_task("Starting audit", total=None)

        def update_progress(phase: str, completed: int | None) -> None:
            suffix = f" ({completed} checked)" if completed is not None else ""
            progress.update(task_id, description=f"{phase}{suffix}")

        report = run_audit(
            args.input_path,
            input_format,
            AuditOptions(
                check_breaches=args.check_breaches,
                hibp_workers=args.hibp_workers,
            ),
            progress=update_progress,
        )

        progress.update(task_id, description="Writing reports")
        report_dir = args.report_dir or args.input_path.parent / "vaultsieve_reports"
        try:
            report_dir.mkdir(parents=True, exist_ok=True)
        except OSError as err:
            raise VaultSieveError(f"Cannot create report directory: {report_dir}") from err
        base_name = args.input_path.stem or "vaultsieve"
        try:
            (report_dir / f"{base_name}.txt").write_text(
                render_text_report(report), encoding="utf-8"
            )
            (report_dir / f"{base_name}.json").write_text(
                render_json_report(report), encoding="utf-8"
            )
            (report_dir / f"{base_name}.html").write_text(
                render_html_report(report), encoding="utf-8"
            )
        except OSError as err:
            raise VaultSieveError(f"Cannot write reports to: {report_dir}") from err

        if args.clean_output is not None:
            progress.update(task_id, description="Writing clean output")
            removed = write_clean_output(
                args.input_path,
                args.clean_output,
                input_format,
                report.credentials,
            )
        else:
            removed = None
        progress.update(task_id, description="Done")

    print_terminal_report(report, min_severity=args.min_severity)
    print(f"Reports written to {report_dir}")
    if removed is not None:
        print(f"Clean output written to {args.clean_output} ({removed} duplicates removed).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

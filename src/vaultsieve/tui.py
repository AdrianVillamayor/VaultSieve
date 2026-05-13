from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm, Prompt

from vaultsieve.audit import run_audit
from vaultsieve.cleaner import write_clean_output
from vaultsieve.errors import VaultSieveError
from vaultsieve.models import AuditOptions, InputFormat
from vaultsieve.reports.html import render_html_report
from vaultsieve.reports.json import render_json_report
from vaultsieve.reports.terminal import print_terminal_report
from vaultsieve.reports.text import render_text_report


def run_tui() -> int:
    console = Console()
    try:
        console.print(Panel.fit("[bold]VaultSieve[/bold]\nPassword vault security assistant"))
        while True:
            console.print("\n[bold]What do you want to do?[/bold]")
            console.print("1. Audit a vault export")
            console.print("2. Show supported input formats")
            console.print("3. Exit")
            choice = Prompt.ask("Choose an option", choices=["1", "2", "3", "q"], default="1")
            if choice == "1":
                _run_guided_audit(console)
            elif choice == "2":
                _show_format_help(console)
            else:
                console.print("Bye.")
                return 0
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled. Bye.[/yellow]")
        return 130
    except VaultSieveError as err:
        console.print(f"[red]Error:[/red] {err}")
        return 1
    return 0


def _run_guided_audit(console: Console) -> None:
    input_value = Prompt.ask("Input file path or 'q' to cancel")
    if input_value.lower() in {"q", "quit", "exit"}:
        console.print("Cancelled.")
        return
    input_path = Path(input_value)
    input_format: InputFormat = Prompt.ask(
        "Input format",
        choices=["bitwarden", "csv"],
        default="bitwarden",
    )
    check_breaches = Confirm.ask(
        "Check Have I Been Pwned? This sends only SHA-1 hash prefixes",
        default=False,
    )
    report_dir = Path(Prompt.ask("Report directory", default="vaultsieve_reports"))

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task_id = progress.add_task("Starting audit", total=None)

        def update_progress(phase: str, completed: int | None) -> None:
            suffix = f" ({completed} checked)" if completed is not None else ""
            progress.update(task_id, description=f"{phase}{suffix}")

        report = run_audit(
            input_path,
            input_format,
            AuditOptions(check_breaches=check_breaches),
            progress=update_progress,
        )
        progress.update(task_id, description="Audit complete")

    print_terminal_report(report, console=console)

    if Confirm.ask("Write TXT, JSON, and HTML reports?", default=True):
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task_id = progress.add_task("Writing reports", total=None)
            try:
                report_dir.mkdir(parents=True, exist_ok=True)
            except OSError as err:
                raise VaultSieveError(f"Cannot create report directory: {report_dir}") from err
            base_name = input_path.stem or "vaultsieve"
            try:
                (report_dir / f"{base_name}.txt").write_text(
                    render_text_report(report), encoding="utf-8"
                )
                progress.update(task_id, description="Writing JSON report")
                (report_dir / f"{base_name}.json").write_text(
                    render_json_report(report), encoding="utf-8"
                )
                progress.update(task_id, description="Writing HTML report")
                (report_dir / f"{base_name}.html").write_text(
                    render_html_report(report), encoding="utf-8"
                )
            except OSError as err:
                raise VaultSieveError(f"Cannot write reports to: {report_dir}") from err
            progress.update(task_id, description="Reports complete")
        console.print(f"Reports written to {report_dir}")

    if Confirm.ask("Create clean output without exact duplicates?", default=False):
        clean_output = Path(Prompt.ask("Clean output path"))
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            progress.add_task("Writing clean output", total=None)
            removed = write_clean_output(input_path, clean_output, input_format, report.credentials)
        console.print(f"Clean output written to {clean_output} ({removed} duplicates removed).")


def _show_format_help(console: Console) -> None:
    console.print("[bold]Supported input formats[/bold]")
    console.print("Bitwarden JSON: standard Bitwarden JSON export; login items use type == 1.")
    console.print("CSV: required columns are name, url, username, password.")

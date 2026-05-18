from __future__ import annotations

from pathlib import Path

from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt

from vaultsieve.assets import copy_logo_assets
from vaultsieve.audit import run_audit
from vaultsieve.cleaner import write_clean_output
from vaultsieve.config import (
    AppConfig,
    config_path,
    load_config,
    parse_output_formats,
    reset_config,
    save_config,
)
from vaultsieve.errors import VaultSieveError
from vaultsieve.models import AuditOptions, InputFormat
from vaultsieve.progress import AuditProgress
from vaultsieve.reports.html import render_html_report
from vaultsieve.reports.json import render_json_report
from vaultsieve.reports.terminal import print_terminal_report
from vaultsieve.reports.text import render_text_report


def run_tui() -> int:
    console = Console()
    try:
        if not config_path().exists():
            _run_first_use_settings(console)
        console.print(Panel.fit("[bold]VaultSieve[/bold]\nPassword vault security assistant"))
        while True:
            console.print("\n[bold]What do you want to do?[/bold]")
            console.print("1. Audit a vault export")
            console.print("2. Show supported input formats")
            console.print("3. Settings")
            console.print("4. Exit")
            choice = Prompt.ask("Choose an option", choices=["1", "2", "3", "4", "q"], default="1")
            if choice == "1":
                _run_guided_audit(console)
            elif choice == "2":
                _show_format_help(console)
            elif choice == "3":
                _run_settings(console)
            else:
                console.print("Bye.")
                return 0
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled. Bye.[/yellow]")
        return 130
    except VaultSieveError as err:
        console.print(f"[red]Error:[/red] {err}")
        return 1


def _run_guided_audit(console: Console) -> None:
    config = load_config()
    input_value = Prompt.ask("Input file path or 'q' to cancel")
    if input_value.lower() in {"q", "quit", "exit"}:
        console.print("Cancelled.")
        return
    input_path = Path(input_value)
    guessed_format = "csv" if input_path.suffix.lower() == ".csv" else "bitwarden"
    input_format: InputFormat = Prompt.ask(
        "Input format",
        choices=["bitwarden", "csv"],
        default=guessed_format,
    )
    check_breaches = Confirm.ask(
        "Check Have I Been Pwned? This sends only SHA-1 hash prefixes",
        default=config.check_breaches,
    )
    check_domains = Confirm.ask(
        "Check whether saved credential domains still exist?",
        default=config.check_domains,
    )
    check_2fa = Confirm.ask(
        "Check services that support TOTP 2FA using 2fa.directory?",
        default=config.check_2fa,
    )
    check_known_breaches = Confirm.ask(
        "Check whether saved services appear in the public HIBP breach catalogue?",
        default=config.check_known_breaches,
    )
    default_report_dir = Path(config.report_dir) if config.report_dir else input_path.parent / "vaultsieve_reports"
    report_dir = Path(Prompt.ask("Report directory", default=str(default_report_dir)))

    with AuditProgress(console) as progress:
        report = run_audit(
            input_path,
            input_format,
            AuditOptions(
                check_breaches=check_breaches,
                check_domains=check_domains,
                check_2fa=check_2fa,
                check_known_breaches=check_known_breaches,
                hibp_workers=config.hibp_workers,
                domain_workers=config.domain_workers,
                min_password_length=config.min_password_length,
            ),
            progress=progress.update,
        )
        progress.update("Audit complete")

    print_terminal_report(report, console=console)

    if Confirm.ask(
        f"Write reports ({', '.join(config.output_formats)})?",
        default=True,
    ):
        with AuditProgress(console) as report_progress:
            report_progress.update("Writing TXT report")
            try:
                report_dir.mkdir(parents=True, exist_ok=True)
            except OSError as err:
                raise VaultSieveError(f"Cannot create report directory: {report_dir}") from err
            base_name = input_path.stem or "vaultsieve"
            html_path = report_dir / f"{base_name}.html"
            try:
                if "txt" in config.output_formats:
                    (report_dir / f"{base_name}.txt").write_text(
                        render_text_report(report), encoding="utf-8"
                    )
                if "json" in config.output_formats:
                    report_progress.update("Writing JSON report")
                    (report_dir / f"{base_name}.json").write_text(
                        render_json_report(report), encoding="utf-8"
                    )
                if "html" in config.output_formats:
                    report_progress.update("Writing HTML report")
                    copy_logo_assets(report_dir)
                    html_path.write_text(render_html_report(report), encoding="utf-8")
            except OSError as err:
                raise VaultSieveError(f"Cannot write reports to: {report_dir}") from err
            report_progress.update("Reports complete")
        console.print(f"Reports written to {report_dir}")
        console.print("Treat reports as sensitive: they exclude passwords but can include account identifiers.")
        if "html" in config.output_formats:
            console.print(f"Open HTML report: {html_path.resolve().as_uri()}")

    if Confirm.ask("Create clean output?", default=False):
        clean_mode = Prompt.ask(
            "What should the clean file remove?",
            choices=["duplicates", "obsolete", "all"],
            default="duplicates",
        )
        suffix = ".json" if input_format == "bitwarden" else ".csv"
        clean_default = input_path.with_name(f"{input_path.stem}_clean{suffix}")
        clean_output = Path(Prompt.ask("Clean output file path", default=str(clean_default)))
        with AuditProgress(console) as clean_progress:
            clean_progress.update("Writing clean output")
            removed = write_clean_output(
                input_path,
                clean_output,
                input_format,
                report.credentials,
                report.findings,
                clean_mode,
            )
            clean_progress.update("Clean output complete")
        console.print(f"Clean output written to {clean_output} ({removed} entries removed).")


def _show_format_help(console: Console) -> None:
    console.print("[bold]Supported input formats[/bold]")
    console.print("Bitwarden JSON: standard Bitwarden JSON export; login items use type == 1.")
    console.print("CSV: required columns are name, url, username, password.")


def _run_settings(console: Console) -> None:
    config = load_config()
    while True:
        values = config.to_dict()
        console.print(f"\n[bold]Settings[/bold] ({config_path()})")
        console.print(f"1. Check Have I Been Pwned by default: {values['check_breaches']}")
        console.print(f"2. Check domains by default: {values['check_domains']}")
        console.print(f"3. Check 2FA availability by default: {values['check_2fa']}")
        console.print(f"4. Check known breached services by default: {values['check_known_breaches']}")
        console.print(f"5. HIBP workers: {values['hibp_workers']}")
        console.print(f"6. Domain workers: {values['domain_workers']}")
        console.print(f"7. Minimum password length: {values['min_password_length']}")
        console.print(f"8. Report directory: {values['report_dir'] or '(next to input)'}")
        console.print(f"9. Output formats: {', '.join(config.output_formats)}")
        console.print("10. Reset all defaults")
        console.print("11. Back")
        choice = Prompt.ask("Setting to change", choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "q"], default="11")
        if choice in {"11", "q"}:
            return
        if choice == "10":
            if Confirm.ask("Reset all settings to defaults?", default=False):
                config = reset_config()
                console.print(f"Saved settings to {config_path()}")
            continue
        config = _updated_config_from_choice(console, config, choice)
        path = save_config(config)
        console.print(f"Saved settings to {path}")


def _updated_config_from_choice(console: Console, config: AppConfig, choice: str) -> AppConfig:
    values = config.to_dict()
    if choice == "1":
        values["check_breaches"] = Confirm.ask("Check Have I Been Pwned by default?", default=config.check_breaches)
    elif choice == "2":
        values["check_domains"] = Confirm.ask("Check domains by default?", default=config.check_domains)
    elif choice == "3":
        values["check_2fa"] = Confirm.ask("Check 2FA availability by default?", default=config.check_2fa)
    elif choice == "4":
        values["check_known_breaches"] = Confirm.ask("Check known breached services by default?", default=config.check_known_breaches)
    elif choice == "5":
        values["hibp_workers"] = _ask_positive_int("HIBP workers", config.hibp_workers)
    elif choice == "6":
        values["domain_workers"] = _ask_positive_int("Domain workers", config.domain_workers)
    elif choice == "7":
        values["min_password_length"] = _ask_positive_int("Minimum password length", config.min_password_length)
    elif choice == "8":
        values["report_dir"] = Prompt.ask(
            "Report directory, empty means next to input",
            default=config.report_dir,
        ).strip()
    elif choice == "9":
        values["output_formats"] = parse_output_formats(
            Prompt.ask(
                "Output formats (html, json, txt, all, or comma-separated)",
                default=",".join(config.output_formats),
            )
        )
    return AppConfig(**values)


def _run_first_use_settings(console: Console) -> None:
    console.print(Panel.fit("[bold]First run setup[/bold]\nChoose defaults once; you can change them later in Settings."))
    config = AppConfig(
        check_breaches=Confirm.ask(
            "Check Have I Been Pwned by default? This sends only SHA-1 hash prefixes",
            default=False,
        ),
        check_domains=Confirm.ask("Check credential domains by default?", default=False),
        check_2fa=Confirm.ask("Check 2FA availability using 2fa.directory by default?", default=False),
        check_known_breaches=Confirm.ask("Check known breached services using the public HIBP catalogue by default?", default=False),
        hibp_workers=_ask_positive_int("HIBP workers", 4),
        domain_workers=_ask_positive_int("Domain workers", 16),
        min_password_length=_ask_positive_int("Minimum password length", 12),
        report_dir=Prompt.ask(
            "Default report directory, empty means next to input",
            default="",
        ).strip(),
        output_formats=parse_output_formats(
            Prompt.ask(
                "Default output formats (html, json, txt, all, or comma-separated)",
                default="all",
            )
        ),
    )
    path = save_config(config)
    console.print(f"Saved settings to {path}")


def _ask_positive_int(label: str, default: int) -> int:
    while True:
        value = Prompt.ask(label, default=str(default))
        try:
            parsed = int(value)
        except ValueError:
            continue
        if parsed > 0:
            return parsed

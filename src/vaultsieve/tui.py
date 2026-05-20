from __future__ import annotations

from pathlib import Path

import questionary
from rich.console import Console
from rich.panel import Panel

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

_STYLE = questionary.Style([
    ("qmark", "fg:cyan bold"),
    ("question", "bold"),
    ("pointer", "fg:cyan bold"),
    ("highlighted", "fg:cyan bold"),
    ("selected", "fg:green"),
])


def _select(message: str, choices: list[questionary.Choice | str], **kwargs) -> str:
    result = questionary.select(message, choices=choices, style=_STYLE, **kwargs).ask()
    if result is None:
        raise KeyboardInterrupt
    return result


def _confirm(message: str, default: bool = False) -> bool:
    result = questionary.confirm(message, default=default, style=_STYLE).ask()
    if result is None:
        raise KeyboardInterrupt
    return result


def _text(message: str, default: str = "") -> str:
    result = questionary.text(message, default=default, style=_STYLE).ask()
    if result is None:
        raise KeyboardInterrupt
    return result


def run_tui() -> int:
    console = Console()
    try:
        if not config_path().exists():
            _run_first_use_settings(console)
        console.print(Panel.fit("[bold]VaultSieve[/bold]\nPassword vault security assistant"))
        while True:
            action = _select("What do you want to do?", [
                questionary.Choice("Audit a vault export", value="audit"),
                questionary.Choice("Show supported input formats", value="formats"),
                questionary.Choice("Settings", value="settings"),
                questionary.Choice("Exit", value="exit"),
            ])
            if action == "audit":
                _run_guided_audit(console)
            elif action == "formats":
                _show_format_help(console)
            elif action == "settings":
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
    input_value = _text("Input file path (or 'q' to cancel)")
    if input_value.lower() in {"q", "quit", "exit"}:
        console.print("Cancelled.")
        return
    input_path = Path(input_value)
    guessed_format = _guess_format(input_path)
    format_choices = [
        questionary.Choice("Bitwarden (JSON)", value="bitwarden"),
        questionary.Choice("Generic CSV", value="csv"),
        questionary.Choice("LastPass (CSV)", value="lastpass"),
        questionary.Choice("Dashlane (CSV / ZIP / JSON)", value="dashlane"),
        questionary.Choice("1Password (CSV / 1PUX)", value="1password"),
        questionary.Choice("KeePass / KeePassXC (CSV / XML)", value="keepass"),
        questionary.Choice("Keeper (CSV / JSON)", value="keeper"),
        questionary.Choice("RoboForm (CSV)", value="roboform"),
    ]
    input_format: InputFormat = _select(
        "Input format",
        format_choices,
        default=guessed_format,
    )
    check_breaches = _confirm(
        "Check Have I Been Pwned? (sends only SHA-1 hash prefixes)",
        default=config.check_breaches,
    )
    check_domains = _confirm(
        "Check whether saved credential domains still exist?",
        default=config.check_domains,
    )
    check_2fa = _confirm(
        "Check services that support TOTP 2FA using 2fa.directory?",
        default=config.check_2fa,
    )
    check_known_breaches = _confirm(
        "Check services in the public HIBP breach catalogue?",
        default=config.check_known_breaches,
    )
    default_report_dir = (
        Path(config.report_dir) if config.report_dir else input_path.parent / "vaultsieve_reports"
    )
    report_dir = Path(_text("Report directory", default=str(default_report_dir)))

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

    if _confirm(f"Write reports ({', '.join(config.output_formats)})?", default=True):
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
        console.print(
            "Treat reports as sensitive: they exclude passwords but can include account identifiers."
        )
        if "html" in config.output_formats:
            console.print(f"Open HTML report: {html_path.resolve().as_uri()}")

    if _confirm("Create clean output?", default=False):
        clean_mode = _select("What should the clean file remove?", [
            questionary.Choice("Exact duplicates only", value="duplicates"),
            questionary.Choice("Obsolete domain entries only", value="obsolete"),
            questionary.Choice("Both duplicates and obsolete", value="all"),
        ])
        suffix = ".json" if input_format == "bitwarden" else ".csv"
        clean_default = input_path.with_name(f"{input_path.stem}_clean{suffix}")
        clean_output = Path(_text("Clean output file path", default=str(clean_default)))
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
    console.print("bitwarden  — Bitwarden JSON export (login items use type == 1)")
    console.print("csv        — Generic CSV with columns: name, url, username, password")
    console.print("lastpass   — LastPass CSV export")
    console.print("dashlane   — Dashlane CSV, ZIP, or JSON export (auto-detected by extension)")
    console.print("1password  — 1Password CSV or 1PUX export (auto-detected by extension)")
    console.print("keepass    — KeePass/KeePassXC CSV or XML export (auto-detected)")
    console.print("keeper     — Keeper CSV or JSON export (auto-detected by extension)")
    console.print("roboform   — RoboForm CSV export (BOM-safe)")


def _run_settings(console: Console) -> None:
    config = load_config()
    while True:
        values = config.to_dict()
        console.print(f"\n[bold]Settings[/bold] ({config_path()})")
        setting = _select("Setting to change", [
            questionary.Choice(
                f"Check Have I Been Pwned by default: {values['check_breaches']}",
                value="check_breaches",
            ),
            questionary.Choice(
                f"Check domains by default: {values['check_domains']}",
                value="check_domains",
            ),
            questionary.Choice(
                f"Check 2FA availability by default: {values['check_2fa']}",
                value="check_2fa",
            ),
            questionary.Choice(
                f"Check known breached services by default: {values['check_known_breaches']}",
                value="check_known_breaches",
            ),
            questionary.Choice(
                f"HIBP workers: {values['hibp_workers']}",
                value="hibp_workers",
            ),
            questionary.Choice(
                f"Domain workers: {values['domain_workers']}",
                value="domain_workers",
            ),
            questionary.Choice(
                f"Minimum password length: {values['min_password_length']}",
                value="min_password_length",
            ),
            questionary.Choice(
                f"Report directory: {values['report_dir'] or '(next to input)'}",
                value="report_dir",
            ),
            questionary.Choice(
                f"Output formats: {', '.join(config.output_formats)}",
                value="output_formats",
            ),
            questionary.Choice("Reset all defaults", value="reset"),
            questionary.Choice("Back", value="back"),
        ])
        if setting == "back":
            return
        if setting == "reset":
            if _confirm("Reset all settings to defaults?"):
                config = reset_config()
                console.print(f"Saved settings to {config_path()}")
            continue
        config = _update_setting(config, setting)
        path = save_config(config)
        console.print(f"Saved settings to {path}")


def _update_setting(config: AppConfig, setting: str) -> AppConfig:
    values = config.to_dict()
    if setting == "check_breaches":
        values["check_breaches"] = _confirm(
            "Check Have I Been Pwned by default?", default=config.check_breaches
        )
    elif setting == "check_domains":
        values["check_domains"] = _confirm(
            "Check domains by default?", default=config.check_domains
        )
    elif setting == "check_2fa":
        values["check_2fa"] = _confirm(
            "Check 2FA availability by default?", default=config.check_2fa
        )
    elif setting == "check_known_breaches":
        values["check_known_breaches"] = _confirm(
            "Check known breached services by default?", default=config.check_known_breaches
        )
    elif setting == "hibp_workers":
        values["hibp_workers"] = _ask_positive_int("HIBP workers", config.hibp_workers)
    elif setting == "domain_workers":
        values["domain_workers"] = _ask_positive_int("Domain workers", config.domain_workers)
    elif setting == "min_password_length":
        values["min_password_length"] = _ask_positive_int(
            "Minimum password length", config.min_password_length
        )
    elif setting == "report_dir":
        values["report_dir"] = _text(
            "Report directory (empty = next to input)", default=config.report_dir
        ).strip()
    elif setting == "output_formats":
        values["output_formats"] = parse_output_formats(
            _text(
                "Output formats (html, json, txt, all, or comma-separated)",
                default=",".join(config.output_formats),
            )
        )
    return AppConfig(**values)


def _run_first_use_settings(console: Console) -> None:
    console.print(
        Panel.fit("[bold]First run setup[/bold]\nChoose defaults once; change later in Settings.")
    )
    config = AppConfig(
        check_breaches=_confirm(
            "Check Have I Been Pwned by default? (sends only SHA-1 hash prefixes)",
            default=False,
        ),
        check_domains=_confirm("Check credential domains by default?", default=False),
        check_2fa=_confirm(
            "Check 2FA availability using 2fa.directory by default?", default=False
        ),
        check_known_breaches=_confirm(
            "Check known breached services using the public HIBP catalogue by default?",
            default=False,
        ),
        hibp_workers=_ask_positive_int("HIBP workers", 4),
        domain_workers=_ask_positive_int("Domain workers", 16),
        min_password_length=_ask_positive_int("Minimum password length", 12),
        report_dir=_text("Default report directory (empty = next to input)", default="").strip(),
        output_formats=parse_output_formats(
            _text(
                "Default output formats (html, json, txt, all, or comma-separated)",
                default="all",
            )
        ),
    )
    path = save_config(config)
    console.print(f"Saved settings to {path}")


def _guess_format(path: Path) -> str:
    ext = path.suffix.lower()
    stem = path.stem.lower()
    if ext == ".xml":
        return "keepass"
    if ext == ".1pux":
        return "1password"
    if ext in {".zip", ".dash"}:
        return "dashlane"
    if ext == ".csv":
        if "lastpass" in stem:
            return "lastpass"
        if "dashlane" in stem:
            return "dashlane"
        if "1password" in stem or "onepassword" in stem:
            return "1password"
        if "keepass" in stem:
            return "keepass"
        if "keeper" in stem:
            return "keeper"
        if "roboform" in stem:
            return "roboform"
        return "csv"
    return "bitwarden"


def _ask_positive_int(label: str, default: int) -> int:
    while True:
        value = _text(label, default=str(default))
        try:
            parsed = int(value)
        except ValueError:
            continue
        if parsed > 0:
            return parsed

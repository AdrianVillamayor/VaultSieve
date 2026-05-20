from __future__ import annotations

import argparse
import logging
from collections.abc import Callable
from pathlib import Path

from rich.console import Console

from vaultsieve import __version__
from vaultsieve.assets import copy_logo_assets
from vaultsieve.audit import run_audit
from vaultsieve.cleaner import write_clean_output
from vaultsieve.config import (
    CONFIG_KEYS,
    config_path,
    load_config,
    reset_config,
    set_config_value,
    unset_config_value,
)
from vaultsieve.errors import VaultSieveError
from vaultsieve.models import AuditOptions, InputFormat
from vaultsieve.progress import AuditProgress
from vaultsieve.reports.html import render_html_report
from vaultsieve.reports.json import render_json_report
from vaultsieve.reports.terminal import print_terminal_report
from vaultsieve.reports.text import render_text_report


def _positive_int(flag: str) -> Callable[[str], int]:
    def parse(value: str) -> int:
        try:
            result = int(value)
        except ValueError:
            raise argparse.ArgumentTypeError(f"{flag} expects an integer")
        if result < 1:
            raise argparse.ArgumentTypeError(f"{flag} must be a positive integer")
        if result > 256:
            raise argparse.ArgumentTypeError(f"{flag} must be at most 256")
        return result
    return parse


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="vaultsieve")
    parser.add_argument("--version", action="version", version=f"vaultsieve {__version__}")
    subparsers = parser.add_subparsers(dest="command")

    audit = subparsers.add_parser("audit", help="Audit an exported vault file.")
    audit.add_argument("input_path", type=Path)
    audit.add_argument(
        "--format",
        choices=["bitwarden", "csv", "lastpass", "dashlane", "1password", "keepass", "keeper", "roboform"],
        required=True,
    )
    audit.add_argument("--check-breaches", action="store_true", default=None)
    audit.add_argument("--no-check-breaches", action="store_false", dest="check_breaches")
    audit.add_argument("--check-domains", action="store_true", default=None)
    audit.add_argument("--no-check-domains", action="store_false", dest="check_domains")
    audit.add_argument("--check-2fa", action="store_true", default=None)
    audit.add_argument("--no-check-2fa", action="store_false", dest="check_2fa")
    audit.add_argument("--check-known-breaches", action="store_true", default=None)
    audit.add_argument("--no-check-known-breaches", action="store_false", dest="check_known_breaches")
    audit.add_argument("--hibp-workers", type=_positive_int("--hibp-workers"))
    audit.add_argument("--domain-workers", type=_positive_int("--domain-workers"))
    audit.add_argument("--min-password-length", type=_positive_int("--min-password-length"))
    audit.add_argument("--report-dir", type=Path)
    audit.add_argument("--clean-output", type=Path)
    audit.add_argument(
        "--clean-mode",
        choices=["duplicates", "obsolete", "all"],
        default="duplicates",
        help="Choose what to remove from clean output.",
    )
    audit.add_argument(
        "--min-severity",
        choices=["critical", "high", "medium", "low", "obsolete"],
        default="low",
    )

    subparsers.add_parser("tui", help="Start the guided terminal interface.")
    config = subparsers.add_parser("config", help="Read or update persistent defaults.")
    config_subparsers = config.add_subparsers(dest="config_command")
    config_subparsers.add_parser("list", help="Show all config values.")
    config_subparsers.add_parser("path", help="Show the config file path.")
    config_subparsers.add_parser("reset", help="Reset all config values to defaults.")
    get_config = config_subparsers.add_parser("get", help="Show one config value.")
    get_config.add_argument("key", choices=CONFIG_KEYS)
    set_config = config_subparsers.add_parser("set", help="Set one config value.")
    set_config.add_argument("key", choices=CONFIG_KEYS)
    set_config.add_argument("value")
    unset_config = config_subparsers.add_parser("unset", help="Reset one config value to default.")
    unset_config.add_argument("key", choices=CONFIG_KEYS)
    return parser


def main(argv: list[str] | None = None) -> int:
    logging.getLogger("vaultsieve").setLevel(logging.ERROR)
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

        if args.command == "config":
            return _run_config_command(args)

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
    config = load_config()
    check_breaches = config.check_breaches if args.check_breaches is None else args.check_breaches
    check_domains = config.check_domains if args.check_domains is None else args.check_domains
    check_2fa = config.check_2fa if args.check_2fa is None else args.check_2fa
    check_known_breaches = config.check_known_breaches if args.check_known_breaches is None else args.check_known_breaches
    hibp_workers = args.hibp_workers if args.hibp_workers is not None else config.hibp_workers
    domain_workers = args.domain_workers if args.domain_workers is not None else config.domain_workers
    min_password_length = args.min_password_length if args.min_password_length is not None else config.min_password_length
    with AuditProgress() as progress:
        report = run_audit(
            args.input_path,
            input_format,
            AuditOptions(
                check_breaches=check_breaches,
                check_domains=check_domains,
                check_2fa=check_2fa,
                check_known_breaches=check_known_breaches,
                hibp_workers=hibp_workers,
                domain_workers=domain_workers,
                min_password_length=min_password_length,
            ),
            progress=progress.update,
        )

        progress.update("Writing reports")
        report_dir = args.report_dir or Path(config.report_dir or args.input_path.parent / "vaultsieve_reports")
        try:
            report_dir.mkdir(parents=True, exist_ok=True)
        except OSError as err:
            raise VaultSieveError(f"Cannot create report directory: {report_dir}") from err
        base_name = args.input_path.stem or "vaultsieve"
        html_path = report_dir / f"{base_name}.html"
        try:
            if "txt" in config.output_formats:
                (report_dir / f"{base_name}.txt").write_text(
                    render_text_report(report), encoding="utf-8"
                )
            if "json" in config.output_formats:
                (report_dir / f"{base_name}.json").write_text(
                    render_json_report(report), encoding="utf-8"
                )
            if "html" in config.output_formats:
                copy_logo_assets(report_dir)
                html_path.write_text(render_html_report(report), encoding="utf-8")
        except OSError as err:
            raise VaultSieveError(f"Cannot write reports to: {report_dir}") from err

        if args.clean_output is not None:
            progress.update("Writing clean output")
            removed = write_clean_output(
                args.input_path,
                args.clean_output,
                input_format,
                report.credentials,
                report.findings,
                args.clean_mode,
            )
        else:
            removed = None
        progress.update("Audit complete")

    print_terminal_report(report, min_severity=args.min_severity)
    print(f"Reports written to {report_dir}")
    print("Treat reports as sensitive: they exclude passwords but can include account identifiers.")
    if "html" in config.output_formats:
        print(f"Open HTML report: {html_path.resolve().as_uri()}")
    if removed is not None:
        print(f"Clean output written to {args.clean_output} ({removed} entries removed).")
    return 0


def _run_config_command(args: argparse.Namespace) -> int:
    command = args.config_command or "list"
    if command == "list":
        config = load_config()
        print(f"Config file: {config_path()}")
        for key, value in config.to_dict().items():
            print(f"{key}={value}")
        return 0
    if command == "get":
        config = load_config()
        print(config.to_dict()[args.key])
        return 0
    if command == "path":
        print(config_path())
        return 0
    if command == "reset":
        reset_config()
        print("Reset all config values")
        return 0
    if command == "set":
        set_config_value(args.key, args.value)
        print(f"Updated {args.key}")
        return 0
    if command == "unset":
        unset_config_value(args.key)
        print(f"Reset {args.key}")
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())

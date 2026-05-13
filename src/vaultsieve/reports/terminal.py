from __future__ import annotations

from rich.console import Console
from rich.panel import Panel

from vaultsieve.models import AuditReport, Severity


def print_terminal_report(
    report: AuditReport,
    *,
    min_severity: Severity = "low",
    console: Console | None = None,
) -> None:
    output = console or Console()
    summary = report.summary_by_severity
    output.print(
        Panel.fit(
            "\n".join(
                [
                    f"[bold]Input:[/bold] {report.input_path}",
                    f"[bold]Format:[/bold] {report.input_format}",
                    f"[bold]Credentials:[/bold] {len(report.credentials)}",
                    f"[bold]Findings:[/bold] {len(report.findings)}",
                    " ".join(
                        [
                            f"[red]critical[/red]={summary['critical']}",
                            f"[orange1]high[/orange1]={summary['high']}",
                            f"[yellow]medium[/yellow]={summary['medium']}",
                            f"[blue]low[/blue]={summary['low']}",
                            f"obsolete={summary['obsolete']}",
                        ]
                    ),
                ]
            ),
            title="VaultSieve audit summary",
        )
    )

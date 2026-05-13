from __future__ import annotations

from rich.console import Console
from rich.table import Table

from vaultsieve.models import AuditReport, SEVERITY_ORDER, Severity


def print_terminal_report(
    report: AuditReport,
    *,
    min_severity: Severity = "low",
    console: Console | None = None,
) -> None:
    output = console or Console()
    output.print(f"[bold]VaultSieve audit:[/bold] {report.input_path}")
    output.print(f"Credentials: {len(report.credentials)}")

    summary = Table(title="Findings by severity")
    summary.add_column("Severity")
    summary.add_column("Count", justify="right")
    for severity, count in report.summary_by_severity.items():
        summary.add_row(severity, str(count))
    output.print(summary)

    max_rank = SEVERITY_ORDER[min_severity]
    findings = [
        finding for finding in report.findings if SEVERITY_ORDER[finding.severity] <= max_rank
    ]
    table = Table(title="Findings")
    table.add_column("Severity")
    table.add_column("Category")
    table.add_column("Credentials")
    table.add_column("Explanation")
    for finding in findings:
        table.add_row(
            finding.severity,
            finding.category,
            ", ".join(finding.credential_ids),
            finding.explanation,
        )
    output.print(table)

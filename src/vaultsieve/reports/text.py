from __future__ import annotations

from vaultsieve.models import AuditReport

MAX_DETAILED_FINDINGS = 50


def render_text_report(report: AuditReport) -> str:
    credential_map = report.credential_map()
    lines = [
        "VaultSieve Audit Report",
        "=" * 24,
        f"Input: {report.input_path}",
        f"Format: {report.input_format}",
        f"Credentials: {len(report.credentials)}",
        "Findings by severity:",
    ]
    for severity, count in report.summary_by_severity.items():
        lines.append(f"- {severity}: {count}")

    lines.append("")
    category_counts: dict[str, int] = {}
    for finding in report.findings:
        category_counts[finding.category] = category_counts.get(finding.category, 0) + 1

    lines.append("Findings by category")
    lines.append("-" * 20)
    if not category_counts:
        lines.append("No findings detected.")
    for category, count in sorted(category_counts.items()):
        lines.append(f"- {category}: {count}")

    lines.append("")
    lines.append(f"Detailed findings (first {MAX_DETAILED_FINDINGS})")
    lines.append("-" * 28)
    if not report.findings:
        lines.append("No findings detected.")
    for index, finding in enumerate(report.findings[:MAX_DETAILED_FINDINGS], start=1):
        lines.append(f"{index}. [{finding.severity}] {finding.category}")
        lines.append(f"   {finding.explanation}")
        lines.append(f"   Recommendation: {finding.recommendation}")
        for credential_id in finding.credential_ids:
            credential = credential_map.get(credential_id)
            if credential is None:
                continue
            urls = ", ".join(credential.urls) if credential.urls else "no URL"
            lines.append(
                f"   - {credential.id}: {credential.name} | {credential.username} | {urls}"
            )
    if len(report.findings) > MAX_DETAILED_FINDINGS:
        lines.append("")
        lines.append(
            f"{len(report.findings) - MAX_DETAILED_FINDINGS} additional findings omitted from TXT. Use the HTML or JSON report for full details."
        )
    return "\n".join(lines) + "\n"

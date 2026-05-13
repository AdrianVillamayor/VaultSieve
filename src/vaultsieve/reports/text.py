from __future__ import annotations

from vaultsieve.models import AuditReport


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
    lines.append("Findings")
    lines.append("-" * 8)
    if not report.findings:
        lines.append("No findings detected.")
    for index, finding in enumerate(report.findings, start=1):
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
    return "\n".join(lines) + "\n"

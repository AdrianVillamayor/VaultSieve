from __future__ import annotations

from html import escape

from vaultsieve.models import AuditReport


def render_html_report(report: AuditReport) -> str:
    rows: list[str] = []
    credential_map = report.credential_map()
    for finding in report.findings:
        refs: list[str] = []
        for credential_id in finding.credential_ids:
            credential = credential_map.get(credential_id)
            if credential is None:
                continue
            refs.append(
                f"{escape(credential.id)}: {escape(credential.name)} "
                f"({escape(credential.username)})"
            )
        rows.append(
            "<tr>"
            f"<td>{escape(finding.severity)}</td>"
            f"<td>{escape(finding.category)}</td>"
            f"<td>{escape(finding.explanation)}</td>"
            f"<td>{escape(finding.recommendation)}</td>"
            f"<td>{'<br>'.join(refs)}</td>"
            "</tr>"
        )

    summary_rows = "".join(
        f"<tr><td>{escape(severity)}</td><td>{count}</td></tr>"
        for severity, count in report.summary_by_severity.items()
    )
    findings_rows = "".join(rows) or "<tr><td colspan='5'>No findings detected.</td></tr>"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>VaultSieve Audit Report</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #17202a; }}
    table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
    th, td {{ border: 1px solid #d5dbdb; padding: 0.5rem; text-align: left; }}
    th {{ background: #edf2f7; }}
  </style>
</head>
<body>
  <h1>VaultSieve Audit Report</h1>
  <p><strong>Input:</strong> {escape(str(report.input_path))}</p>
  <p><strong>Format:</strong> {escape(report.input_format)}</p>
  <p><strong>Credentials:</strong> {len(report.credentials)}</p>
  <h2>Summary</h2>
  <table><tr><th>Severity</th><th>Count</th></tr>{summary_rows}</table>
  <h2>Findings</h2>
  <table>
    <tr><th>Severity</th><th>Category</th><th>Explanation</th><th>Recommendation</th><th>Credentials</th></tr>
    {findings_rows}
  </table>
</body>
</html>
"""

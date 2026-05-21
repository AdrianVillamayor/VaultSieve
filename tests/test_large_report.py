from pathlib import Path

from vaultsieve.models import AuditReport, Credential, Finding
from vaultsieve.reports.html import render_html_report


def test_large_html_report_renders_without_plaintext_passwords(tmp_path: Path) -> None:
    credentials = tuple(
        Credential(
            id=f"csv:{index}",
            source="csv",
            source_index=index,
            name=f"Account {index}",
            username=f"user{index}@example.com",
            password=f"Secret-{index}",
            urls=(f"https://service{index % 20}.example.com",),
        )
        for index in range(250)
    )
    findings = tuple(
        Finding(
            severity="medium",
            category="weak",
            credential_ids=(f"csv:{index}",),
            explanation="This password is shorter than 12 characters.",
            recommendation="Replace it with a longer unique password.",
        )
        for index in range(120)
    )
    report = AuditReport(
        input_path=tmp_path / "large.csv",
        input_format="csv",
        credentials=credentials,
        findings=findings,
    )

    html = render_html_report(report)

    assert "class=\"findings-table\"" in html
    assert "Vault health at a glance" in html
    assert "Action board" in html
    assert "Cleanup plan" not in html
    assert "Secret-1" not in html
    assert html.count("<tr class=\"finding-row") == 120

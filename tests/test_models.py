from pathlib import Path

from vaultsieve.models import AuditReport, Credential, Finding


def test_safe_report_does_not_include_plaintext_password() -> None:
    credential = Credential(
        id="csv:0",
        source="csv",
        source_index=0,
        name="Example",
        username="alice",
        password="secret-password",
        urls=("https://example.com",),
    )
    report = AuditReport(
        input_path=Path("input.csv"),
        input_format="csv",
        credentials=(credential,),
        findings=(
            Finding(
                severity="high",
                category="reuse",
                credential_ids=("csv:0",),
                explanation="Password reused.",
                recommendation="Change it.",
            ),
        ),
    )

    assert "secret-password" not in str(report.to_safe_dict())

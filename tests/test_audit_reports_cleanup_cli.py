import csv
import json

import pytest

from vaultsieve.audit import run_audit
from vaultsieve.cleaner import write_clean_output
from vaultsieve.cli import main
from vaultsieve.errors import VaultSieveError
from vaultsieve.models import AuditOptions, AuditReport, Credential, Finding
from vaultsieve.reports.html import render_html_report
from vaultsieve.reports.json import render_json_report


def write_bitwarden_fixture(path) -> None:
    older_item = {
        "type": 1,
        "name": "Example",
        "revisionDate": "2024-01-01T00:00:00Z",
        "login": {
            "username": "alice",
            "password": "Secret123!",
            "uris": [{"uri": "https://example.com"}],
        },
    }
    newer_item = {
        **older_item,
        "revisionDate": "2024-02-01T00:00:00Z",
    }
    path.write_text(json.dumps({"items": [older_item, newer_item]}), encoding="utf-8")


def test_run_audit_and_reports_exclude_plaintext_password(tmp_path) -> None:
    path = tmp_path / "export.json"
    write_bitwarden_fixture(path)

    report = run_audit(path, "bitwarden", AuditOptions())

    assert len(report.credentials) == 2
    assert any(finding.category == "duplicate" for finding in report.findings)
    assert "Secret123!" not in render_json_report(report)
    assert "Secret123!" not in render_html_report(report)


def test_html_report_has_dashboard_filters_and_escapes_content(tmp_path) -> None:
    report = AuditReport(
        input_path=tmp_path / "export.json",
        input_format="bitwarden",
        credentials=(
            Credential(
                id="bitwarden:0",
                source="bitwarden",
                source_index=0,
                name="<script>alert(1)</script>",
                username="alice",
                password="never-render-this",
                urls=("https://example.com/?q=<x>",),
            ),
        ),
        findings=(
            Finding(
                severity="critical",
                category="breached",
                credential_ids=("bitwarden:0",),
                explanation="Password appears in breach data.",
                recommendation="Change it immediately.",
            ),
            Finding(
                severity="medium",
                category="two_factor_not_stored",
                credential_ids=("bitwarden:0",),
                explanation="This service supports TOTP-based 2FA, but this vault entry does not include a stored TOTP secret.",
                recommendation="Confirm 2FA is enabled for this account.",
            ),
        ),
    )

    html = render_html_report(report)

    assert "id=\"search\"" in html
    assert "id=\"severity-filter\"" in html
    assert "overflow-y: auto" in html
    assert "max-height: min(760px, 64vh)" in html
    assert "radial-gradient(circle, var(--dot)" in html
    assert "--accent-soft" in html
    assert "rel=\"icon\"" in html
    assert "VaultSieve" in html
    assert "class=\"brand-icon\"" in html
    assert "What to do first" in html
    assert "What VaultSieve understood" in html
    assert "Health score" in html
    assert "Change 1 breached password entries first." in html
    assert "2FA Directory" in html
    assert "data-severity=\"critical\"" in html
    assert "Password vault audit" in html
    assert "never-render-this" not in html
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html


def test_bitwarden_clean_output_removes_exact_duplicates(tmp_path) -> None:
    input_path = tmp_path / "export.json"
    output_path = tmp_path / "clean.json"
    write_bitwarden_fixture(input_path)
    report = run_audit(input_path, "bitwarden")

    removed = write_clean_output(input_path, output_path, "bitwarden", report.credentials)

    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert removed == 1
    assert len(data["items"]) == 1


def test_csv_clean_output_removes_exact_duplicates(tmp_path) -> None:
    input_path = tmp_path / "passwords.csv"
    output_path = tmp_path / "clean.csv"
    input_path.write_text(
        "name,url,username,password,updated_at\n"
        "Example,https://example.com,alice,Secret123!,2024-01-01T00:00:00Z\n"
        "Example,https://example.com,alice,Secret123!,2024-02-01T00:00:00Z\n",
        encoding="utf-8",
    )
    report = run_audit(input_path, "csv")

    removed = write_clean_output(input_path, output_path, "csv", report.credentials)

    with output_path.open("r", encoding="utf-8", newline="") as file:
        rows = list(csv.DictReader(file))
    assert removed == 1
    assert len(rows) == 1


def test_run_audit_can_check_2fa_with_injected_lookup(tmp_path) -> None:
    input_path = tmp_path / "passwords.csv"
    input_path.write_text(
        "name,url,username,password\n"
        "Example,https://example.com,alice,Secret123!\n",
        encoding="utf-8",
    )

    report = run_audit(
        input_path,
        "csv",
        AuditOptions(check_2fa=True),
        two_factor_lookup=lambda: {"example.com": {}},
    )

    assert any(finding.category == "two_factor_not_stored" for finding in report.findings)


def test_csv_clean_output_can_remove_obsolete_entries(tmp_path) -> None:
    input_path = tmp_path / "passwords.csv"
    output_path = tmp_path / "clean.csv"
    input_path.write_text(
        "name,url,username,password\n"
        "Old,https://gone.test,alice,Secret123!\n"
        "Active,https://example.com,bob,Better123!\n",
        encoding="utf-8",
    )
    report = run_audit(
        input_path,
        "csv",
        AuditOptions(check_domains=True),
        domain_lookup=lambda domain: domain != "gone.test",
    )

    removed = write_clean_output(
        input_path,
        output_path,
        "csv",
        report.credentials,
        report.findings,
        "obsolete",
    )

    with output_path.open("r", encoding="utf-8", newline="") as file:
        rows = list(csv.DictReader(file))
    assert removed == 1
    assert [row["name"] for row in rows] == ["Active"]


def test_csv_clean_output_all_removes_duplicates_and_obsolete(tmp_path) -> None:
    input_path = tmp_path / "passwords.csv"
    output_path = tmp_path / "clean.csv"
    input_path.write_text(
        "name,url,username,password\n"
        "Old,https://gone.test,alice,Secret123!\n"
        "Dup,https://example.com,bob,Better123!\n"
        "Dup,https://example.com,bob,Better123!\n"
        "Keep,https://example.org,eve,Another123!\n",
        encoding="utf-8",
    )
    report = run_audit(
        input_path,
        "csv",
        AuditOptions(check_domains=True),
        domain_lookup=lambda domain: domain != "gone.test",
    )

    removed = write_clean_output(
        input_path,
        output_path,
        "csv",
        report.credentials,
        report.findings,
        "all",
        {"csv:2"},
    )

    with output_path.open("r", encoding="utf-8", newline="") as file:
        rows = list(csv.DictReader(file))
    assert removed == 2
    assert [row["name"] for row in rows] == ["Dup", "Keep"]


def test_clean_output_rejects_directory_path(tmp_path) -> None:
    input_path = tmp_path / "export.json"
    write_bitwarden_fixture(input_path)
    report = run_audit(input_path, "bitwarden")

    with pytest.raises(VaultSieveError, match="must be a file path"):
        write_clean_output(input_path, tmp_path, "bitwarden", report.credentials)


def test_cli_audit_smoke(tmp_path) -> None:
    input_path = tmp_path / "export.json"
    report_dir = tmp_path / "reports"
    clean_path = tmp_path / "clean.json"
    write_bitwarden_fixture(input_path)

    exit_code = main(
        [
            "audit",
            str(input_path),
            "--format",
            "bitwarden",
            "--report-dir",
            str(report_dir),
            "--clean-output",
            str(clean_path),
            "--clean-mode",
            "obsolete",
            "--hibp-workers",
            "2",
            "--domain-workers",
            "2",
        ]
    )

    assert exit_code == 0
    assert (report_dir / "export.txt").exists()
    assert (report_dir / "export.json").exists()
    assert (report_dir / "export.html").exists()
    assert (report_dir / "vaultsieve-icon.svg").exists()
    assert (report_dir / "vaultsieve-wordmark.svg").exists()
    assert clean_path.exists()


def test_cli_default_report_dir_is_next_to_input(tmp_path) -> None:
    input_dir = tmp_path / "inputs"
    input_dir.mkdir()
    input_path = input_dir / "export.json"
    write_bitwarden_fixture(input_path)

    exit_code = main(["audit", str(input_path), "--format", "bitwarden"])

    default_report_dir = input_dir / "vaultsieve_reports"
    assert exit_code == 0
    assert (default_report_dir / "export.txt").exists()
    assert (default_report_dir / "export.json").exists()
    assert (default_report_dir / "export.html").exists()
    assert (default_report_dir / "vaultsieve-icon.svg").exists()
    assert (default_report_dir / "vaultsieve-wordmark.svg").exists()


def test_cli_missing_file_returns_clean_error(capsys) -> None:
    exit_code = main(["audit", "missing.json", "--format", "bitwarden"])

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "Input file does not exist" in captured.err
    assert "Traceback" not in captured.err


def test_cli_outputs_only_summary_not_finding_details(tmp_path, capsys) -> None:
    input_path = tmp_path / "export.json"
    report_dir = tmp_path / "reports"
    write_bitwarden_fixture(input_path)

    exit_code = main(
        [
            "audit",
            str(input_path),
            "--format",
            "bitwarden",
            "--report-dir",
            str(report_dir),
        ]
    )

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "VaultSieve audit summary" in captured.out
    assert "Findings:" in captured.out
    assert "Open HTML report: file://" in captured.out
    assert "These credentials are exact duplicates" not in captured.out
    assert "bitwarden:0" not in captured.out

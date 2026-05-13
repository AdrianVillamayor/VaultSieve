import csv
import json

from vaultsieve.audit import run_audit
from vaultsieve.cleaner import write_clean_output
from vaultsieve.cli import main
from vaultsieve.models import AuditOptions, AuditReport, Credential, Finding
from vaultsieve.reports.html import render_html_report
from vaultsieve.reports.json import render_json_report


def write_bitwarden_fixture(path) -> None:
    item = {
        "type": 1,
        "name": "Example",
        "login": {
            "username": "alice",
            "password": "Secret123!",
            "uris": [{"uri": "https://example.com"}],
        },
    }
    path.write_text(json.dumps({"items": [item, item]}), encoding="utf-8")


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
        ),
    )

    html = render_html_report(report)

    assert "id=\"search\"" in html
    assert "id=\"severity-filter\"" in html
    assert "overflow-y: auto" in html
    assert "max-height: min(820px, 62vh)" in html
    assert "data-severity=\"critical\"" in html
    assert "Password Vault Audit" in html
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
        "name,url,username,password\n"
        "Example,https://example.com,alice,Secret123!\n"
        "Example,https://example.com,alice,Secret123!\n",
        encoding="utf-8",
    )
    report = run_audit(input_path, "csv")

    removed = write_clean_output(input_path, output_path, "csv", report.credentials)

    with output_path.open("r", encoding="utf-8", newline="") as file:
        rows = list(csv.DictReader(file))
    assert removed == 1
    assert len(rows) == 1


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
            "--hibp-workers",
            "2",
        ]
    )

    assert exit_code == 0
    assert (report_dir / "export.txt").exists()
    assert (report_dir / "export.json").exists()
    assert (report_dir / "export.html").exists()
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
    assert "These credentials are exact duplicates" not in captured.out
    assert "bitwarden:0" not in captured.out

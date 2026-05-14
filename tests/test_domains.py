import socket

from vaultsieve.analyzers.domains import analyze_domains, domain_exists, extract_domain
from vaultsieve.audit import run_audit
from vaultsieve.models import AuditOptions, Credential


def credential(id_: str, urls: tuple[str, ...]) -> Credential:
    return Credential(
        id=id_,
        source="csv",
        source_index=int(id_.split(":")[-1]),
        name="Example",
        username="alice",
        password="Secret123!",
        urls=urls,
    )


def test_extract_domain_normalizes_urls() -> None:
    assert extract_domain("https://www.example.com/login") == "example.com"
    assert extract_domain("example.org/path") == "example.org"
    assert extract_domain("androidapp://cat.bcn.smoubcn") == ""
    assert extract_domain("iosapp://123456789") == ""
    assert extract_domain("") == ""


def test_analyze_domains_reports_missing_domain_once_for_affected_credentials() -> None:
    calls: list[str] = []

    def lookup(domain: str) -> bool:
        calls.append(domain)
        return domain != "missing.test"

    findings = analyze_domains(
        (
            credential("csv:0", ("https://missing.test/login",)),
            credential("csv:1", ("https://missing.test/account",)),
            credential("csv:2", ("https://example.com",)),
        ),
        lookup,
        max_workers=2,
    )

    assert sorted(calls) == ["example.com", "missing.test"]
    assert len(findings) == 1
    assert findings[0].severity == "obsolete"
    assert findings[0].category == "domain_missing"
    assert findings[0].credential_ids == ("csv:0", "csv:1")


def test_domain_exists_checks_www_variant_before_marking_missing(monkeypatch) -> None:
    calls: list[str] = []

    def getaddrinfo(domain: str, _port: object) -> object:
        calls.append(domain)
        if domain == "example.test":
            raise socket.gaierror("not this host")
        return object()

    monkeypatch.setattr("socket.getaddrinfo", getaddrinfo)

    assert domain_exists("example.test") is True
    assert calls == ["example.test", "www.example.test"]


def test_run_audit_can_check_domains_with_injected_lookup(tmp_path) -> None:
    input_path = tmp_path / "passwords.csv"
    input_path.write_text(
        "name,url,username,password\n"
        "Old,https://gone.test,alice,Secret123!\n",
        encoding="utf-8",
    )

    report = run_audit(
        input_path,
        "csv",
        AuditOptions(check_domains=True),
        domain_lookup=lambda _domain: False,
    )

    assert any(finding.category == "domain_missing" for finding in report.findings)

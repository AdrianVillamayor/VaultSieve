from vaultsieve.analyzers.breaches import analyze_breaches, is_password_breached
from vaultsieve.analyzers.duplicates import analyze_duplicates, duplicate_removal_ids
from vaultsieve.analyzers.passwords import analyze_password_quality
from vaultsieve.models import Credential


def credential(id_: str, password: str, name: str = "Example") -> Credential:
    return Credential(
        id=id_,
        source="csv",
        source_index=int(id_.split(":")[-1]),
        name=name,
        username="alice",
        password=password,
        urls=("https://example.com",),
    )


def test_duplicate_and_reuse_findings() -> None:
    credentials = (
        credential("csv:0", "Secret123!"),
        credential("csv:1", "Secret123!"),
        Credential("csv:2", "csv", 2, "Other", "bob", "Secret123!", ("https://other.test",)),
    )

    findings = analyze_duplicates(credentials)

    assert {finding.category for finding in findings} == {"duplicate", "reuse"}
    assert duplicate_removal_ids(credentials) == {"csv:1"}


def test_password_quality_findings() -> None:
    credentials = (
        credential("csv:0", ""),
        credential("csv:1", "short"),
        credential("csv:2", "example2026", name="Example"),
    )

    findings = analyze_password_quality(credentials)

    categories = [finding.category for finding in findings]
    assert "empty" in categories
    assert "weak" in categories
    assert "similar" in categories


def test_breach_lookup_uses_prefix_only() -> None:
    seen_prefixes: list[str] = []

    def lookup(prefix: str) -> str:
        seen_prefixes.append(prefix)
        return "" if len(prefix) == 5 else "bad"

    assert not is_password_breached("not-breached", lookup)
    assert seen_prefixes == [seen_prefixes[0][:5]]
    assert len(seen_prefixes[0]) == 5


def test_analyze_breaches_reports_breached_password() -> None:
    import hashlib

    password = "breached"
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()

    findings = analyze_breaches((credential("csv:0", password),), lambda prefix: f"{digest[5:]}:1")

    assert len(findings) == 1
    assert findings[0].category == "breached"


def test_analyze_breaches_checks_unique_passwords_once() -> None:
    calls: list[str] = []

    def lookup(prefix: str) -> str:
        calls.append(prefix)
        return ""

    findings = analyze_breaches(
        (
            credential("csv:0", "shared-password"),
            credential("csv:1", "shared-password"),
            credential("csv:2", "other-password"),
        ),
        lookup,
        max_workers=2,
    )

    assert findings == ()
    assert len(calls) == 2


def test_analyze_breaches_reports_lookup_failures() -> None:
    def lookup(_prefix: str) -> str:
        raise OSError("network down")

    findings = analyze_breaches((credential("csv:0", "password"),), lookup)

    assert len(findings) == 1
    assert findings[0].category == "input_issue"

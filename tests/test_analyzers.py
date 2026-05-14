from vaultsieve.analyzers.breaches import analyze_breaches, is_password_breached
from vaultsieve.analyzers.duplicates import (
    analyze_duplicates,
    duplicate_cleanup_plan,
    duplicate_removal_ids,
)
from vaultsieve.analyzers.passwords import analyze_password_quality
from vaultsieve.models import Credential


def credential(
    id_: str,
    password: str,
    name: str = "Example",
    raw: dict[str, object] | None = None,
) -> Credential:
    return Credential(
        id=id_,
        source="csv",
        source_index=int(id_.split(":")[-1]),
        name=name,
        username="alice",
        password=password,
        urls=("https://example.com",),
        raw=raw,
    )


def test_duplicate_and_reuse_findings() -> None:
    credentials = (
        credential("csv:0", "Secret123!", raw={"updated_at": "2024-01-01T00:00:00Z"}),
        credential("csv:1", "Secret123!", raw={"updated_at": "2024-02-01T00:00:00Z"}),
        Credential("csv:2", "csv", 2, "Other", "bob", "Secret123!", ("https://other.test",)),
    )

    findings = analyze_duplicates(credentials)

    assert {finding.category for finding in findings} == {"duplicate", "reuse"}
    assert duplicate_removal_ids(credentials) == {"csv:0"}


def test_duplicate_cleanup_plan_keeps_ambiguous_groups_for_review() -> None:
    credentials = (
        credential("csv:0", "Secret123!"),
        credential("csv:1", "Secret123!"),
    )

    decisions = duplicate_cleanup_plan(credentials)

    assert decisions[0].keep_id is None
    assert decisions[0].remove_ids == ()
    assert duplicate_removal_ids(credentials) == set()


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


def test_password_quality_skips_passkey_without_password_and_ssh_key() -> None:
    credentials = (
        Credential("csv:0", "csv", 0, "Passkey", "alice", "", (), True, False),
        Credential("csv:1", "csv", 1, "SSH", "", "", (), False, True),
    )

    assert analyze_password_quality(credentials) == ()


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


def test_analyze_breaches_skips_ssh_keys() -> None:
    credentials = (Credential("csv:0", "csv", 0, "SSH", "", "password", (), False, True),)

    assert analyze_breaches(credentials, lambda _prefix: "bad") == ()

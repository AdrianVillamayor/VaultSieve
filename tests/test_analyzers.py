from vaultsieve.analyzers.breaches import analyze_breaches, is_password_breached
from vaultsieve.analyzers.domain_concentration import analyze_domain_concentration
from vaultsieve.analyzers.domains import analyze_domains
from vaultsieve.analyzers.duplicates import (
    analyze_duplicates,
    duplicate_cleanup_plan,
    duplicate_removal_ids,
)
from vaultsieve.analyzers.insecure_http import analyze_insecure_http
from vaultsieve.analyzers.known_breaches import analyze_known_breaches
from vaultsieve.analyzers.passwords import analyze_password_quality
from vaultsieve.analyzers.two_factor import analyze_two_factor
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
        Credential("csv:0", "csv", 0, "Passkey", "alice", "", (), True, False, False),
        Credential("csv:1", "csv", 1, "SSH", "", "", (), False, False, True),
        Credential(
            "csv:2",
            "csv",
            2,
            "App",
            "alice",
            "",
            ("androidapp://com.example",),
            False,
            False,
            False,
        ),
    )

    assert analyze_password_quality(credentials) == ()


def test_analyze_insecure_http_reports_http_urls_only() -> None:
    credentials = (
        Credential("csv:0", "csv", 0, "Bad", "alice", "Secret123!", ("http://example.com",)),
        Credential("csv:1", "csv", 1, "Good", "alice", "Secret123!", ("https://example.com",)),
        Credential("csv:2", "csv", 2, "App", "alice", "Secret123!", ("androidapp://com.example",)),
        Credential("csv:3", "csv", 3, "SSH", "", "", ("http://example.com",), False, False, True),
    )

    findings = analyze_insecure_http(credentials, lambda _url: False)

    assert len(findings) == 1
    assert findings[0].category == "insecure_http"
    assert findings[0].credential_ids == ("csv:0",)


def test_analyze_insecure_http_skips_http_urls_that_redirect_to_https() -> None:
    credentials = (
        Credential("csv:0", "csv", 0, "Redirect", "alice", "Secret123!", ("http://example.com",)),
    )

    assert analyze_insecure_http(credentials, lambda _url: True) == ()


def test_analyze_insecure_http_checks_each_unique_url_once() -> None:
    calls: list[str] = []
    credentials = tuple(
        Credential(f"csv:{index}", "csv", index, "Same", "alice", "Secret123!", ("http://example.com",))
        for index in range(10)
    )

    def redirect_check(url: str) -> bool:
        calls.append(url)
        return False

    findings = analyze_insecure_http(credentials, redirect_check)

    assert len(findings) == 10
    assert calls == ["http://example.com"]


def test_analyze_domain_concentration_reports_many_accounts_on_same_domain() -> None:
    credentials = tuple(
        Credential(
            f"csv:{index}",
            "csv",
            index,
            f"Example {index}",
            f"user{index}@example.com",
            f"Secret{index}!",
            (f"https://login.example.com/{index}",),
        )
        for index in range(5)
    )

    findings = analyze_domain_concentration(credentials)

    assert len(findings) == 1
    assert findings[0].category == "domain_concentration"
    assert "5 saved entries" in findings[0].explanation


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
    credentials = (Credential("csv:0", "csv", 0, "SSH", "", "password", (), False, False, True),)

    assert analyze_breaches(credentials, lambda _prefix: "bad") == ()


def test_analyze_two_factor_reports_totp_capable_service_without_stored_totp() -> None:
    findings = analyze_two_factor(
        (credential("csv:0", "Secret123!"),),
        lambda: {"example.com": {"documentation": "https://example.com/2fa"}},
    )

    assert len(findings) == 1
    assert findings[0].category == "two_factor_not_stored"
    assert "https://example.com/2fa" in findings[0].recommendation


def test_analyze_two_factor_skips_totp_passkey_and_ssh_entries() -> None:
    credentials = (
        Credential("csv:0", "csv", 0, "TOTP", "alice", "Secret123!", ("https://example.com",), False, True, False),
        Credential("csv:1", "csv", 1, "Passkey", "alice", "", ("https://example.com",), True, False, False),
        Credential("csv:2", "csv", 2, "SSH", "", "", ("https://example.com",), False, False, True),
    )

    assert analyze_two_factor(credentials, lambda: {"example.com": {}}) == ()


def test_analyze_known_breaches_reports_public_breach_history() -> None:
    findings = analyze_known_breaches(
        (credential("csv:0", "Secret123!"),),
        lambda: {
            "example.com": [
                {"Title": "Example", "Name": "Example", "BreachDate": "2020-01-01"}
            ]
        },
    )

    assert len(findings) == 1
    assert findings[0].category == "service_known_breach"
    assert "does not mean your email" in findings[0].explanation


def test_analyze_known_breaches_skips_apps_and_ssh_keys() -> None:
    credentials = (
        Credential("csv:0", "csv", 0, "App", "alice", "Secret123!", ("androidapp://com.example",)),
        Credential("csv:1", "csv", 1, "SSH", "", "", ("https://example.com",), False, False, True),
    )

    assert analyze_known_breaches(credentials, lambda: {"example.com": [{}]}) == ()


def test_analyze_domain_concentration_ignores_below_threshold() -> None:
    credentials = tuple(
        Credential(
            f"csv:{index}",
            "csv",
            index,
            f"Example {index}",
            f"user{index}@example.com",
            f"Secret{index}!",
            (f"https://login.example.com/{index}",),
        )
        for index in range(3)
    )

    assert analyze_domain_concentration(credentials) == ()


def test_analyze_domain_concentration_skips_ssh_keys() -> None:
    credentials = tuple(
        Credential(
            f"csv:{index}",
            "csv",
            index,
            f"SSH Key {index}",
            "",
            "",
            ("https://login.example.com",),
            False,
            False,
            True,
        )
        for index in range(5)
    )

    assert analyze_domain_concentration(credentials) == ()


def test_analyze_domain_concentration_custom_threshold() -> None:
    credentials = tuple(
        Credential(
            f"csv:{index}",
            "csv",
            index,
            f"Example {index}",
            f"user{index}@example.com",
            f"Secret{index}!",
            (f"https://login.example.com/{index}",),
        )
        for index in range(3)
    )

    findings = analyze_domain_concentration(credentials, min_accounts=3)

    assert len(findings) == 1
    assert findings[0].category == "domain_concentration"


def test_analyze_insecure_http_handles_redirect_check_failure() -> None:
    credentials = (
        Credential("csv:0", "csv", 0, "Bad", "alice", "Secret123!", ("http://example.com",)),
    )

    def failing_redirect_check(url: str) -> bool:
        raise Exception("network error")

    findings = analyze_insecure_http(credentials, failing_redirect_check)

    assert len(findings) == 1
    assert findings[0].category == "insecure_http"


def test_analyze_domains_reports_missing_domain() -> None:
    credentials = (
        Credential("csv:0", "csv", 0, "Gone", "alice", "Secret123!", ("https://gone.example.com",)),
    )

    findings = analyze_domains(credentials, lookup=lambda _domain: False)

    assert len(findings) == 1
    assert findings[0].category == "domain_missing"


def test_analyze_domains_handles_lookup_failure() -> None:
    credentials = (
        Credential("csv:0", "csv", 0, "Broken", "alice", "Secret123!", ("https://broken.example.com",)),
    )

    def failing_lookup(domain: str) -> bool:
        raise Exception("DNS failure")

    findings = analyze_domains(credentials, lookup=failing_lookup)

    assert findings == ()

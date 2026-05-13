from __future__ import annotations

from collections import defaultdict

from vaultsieve.models import Credential, Finding, normalize


def duplicate_key(credential: Credential) -> tuple[str, str, str, tuple[str, ...]]:
    return (
        normalize(credential.name),
        normalize(credential.username),
        credential.password,
        tuple(sorted(normalize(url) for url in credential.urls if normalize(url))),
    )


def analyze_duplicates(credentials: tuple[Credential, ...]) -> tuple[Finding, ...]:
    by_exact: dict[tuple[str, str, str, tuple[str, ...]], list[Credential]] = defaultdict(list)
    by_password: dict[str, list[Credential]] = defaultdict(list)

    for credential in credentials:
        by_exact[duplicate_key(credential)].append(credential)
        if credential.password:
            by_password[credential.password].append(credential)

    findings: list[Finding] = []
    for group in by_exact.values():
        if len(group) > 1:
            findings.append(
                Finding(
                    severity="high",
                    category="duplicate",
                    credential_ids=tuple(credential.id for credential in group),
                    explanation="These credentials are exact duplicates.",
                    recommendation="Keep one entry and remove the later duplicate entries after verifying them.",
                )
            )

    for group in by_password.values():
        unique_exact_keys = {duplicate_key(credential) for credential in group}
        if len(group) > 1 and len(unique_exact_keys) > 1:
            findings.append(
                Finding(
                    severity="high",
                    category="reuse",
                    credential_ids=tuple(credential.id for credential in group),
                    explanation="The same password is reused by multiple different entries.",
                    recommendation="Change these entries so each account has a unique password.",
                )
            )

    return tuple(findings)


def duplicate_removal_ids(credentials: tuple[Credential, ...]) -> set[str]:
    grouped: dict[tuple[str, str, str, tuple[str, ...]], list[Credential]] = defaultdict(list)
    for credential in credentials:
        grouped[duplicate_key(credential)].append(credential)

    remove: set[str] = set()
    for group in grouped.values():
        for credential in group[1:]:
            remove.add(credential.id)
    return remove

from __future__ import annotations

from collections import defaultdict

from vaultsieve.analyzers.domains import extract_domain
from vaultsieve.models import Credential, Finding


def analyze_domain_concentration(
    credentials: tuple[Credential, ...],
    *,
    min_accounts: int = 5,
) -> tuple[Finding, ...]:
    credentials_by_domain: dict[str, list[Credential]] = defaultdict(list)
    for credential in credentials:
        if credential.is_ssh_key:
            continue
        domains = {d for url in credential.urls if (d := extract_domain(url))}
        for domain in domains:
            credentials_by_domain[domain].append(credential)

    findings: list[Finding] = []
    for domain, group in sorted(credentials_by_domain.items()):
        if len(group) < min_accounts:
            continue
        unique_usernames = {credential.username.strip().lower() for credential in group if credential.username.strip()}
        unique_passwords = {credential.password for credential in group if credential.password}
        findings.append(
            Finding(
                severity="low",
                category="domain_concentration",
                credential_ids=tuple(credential.id for credential in group),
                explanation=f"The domain {domain} has {len(group)} saved entries, {len(unique_usernames)} usernames, and {len(unique_passwords)} distinct passwords.",
                recommendation="Review whether these accounts are still needed, remove stale duplicates, and make sure each active account has a unique password.",
            )
        )
    return tuple(findings)

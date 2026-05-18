from __future__ import annotations

from urllib.parse import urlparse

from vaultsieve.models import Credential, Finding


def analyze_insecure_http(credentials: tuple[Credential, ...]) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for credential in credentials:
        if credential.is_ssh_key:
            continue
        insecure_urls = tuple(url for url in credential.urls if _is_insecure_http(url))
        if not insecure_urls:
            continue
        findings.append(
            Finding(
                severity="medium",
                category="insecure_http",
                credential_ids=(credential.id,),
                explanation="This entry contains an insecure http:// URL.",
                recommendation="Use HTTPS for this service if it supports encrypted connections.",
            )
        )
    return tuple(findings)


def _is_insecure_http(url: str) -> bool:
    candidate = url.strip()
    if not candidate or "://" not in candidate:
        return False
    parsed = urlparse(candidate)
    return parsed.scheme.lower() == "http"

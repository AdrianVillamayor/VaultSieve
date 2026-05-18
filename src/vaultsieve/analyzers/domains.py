from __future__ import annotations

import logging
import socket
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from vaultsieve.models import Credential, Finding

logger = logging.getLogger(__name__)

DomainLookupFn = Callable[[str], bool]
ProgressFn = Callable[[str], None]


def extract_domain(url: str) -> str:
    candidate = url.strip()
    if not candidate:
        return ""
    has_scheme = "://" in candidate
    if not has_scheme:
        candidate = f"https://{candidate}"
    parsed = urlparse(candidate)
    if parsed.scheme not in {"http", "https"}:
        return ""
    hostname = parsed.hostname or ""
    return hostname.lower().removeprefix("www.")


def domain_exists(domain: str) -> bool:
    candidates = (domain,) if domain.startswith("www.") else (domain, f"www.{domain}")
    for candidate in candidates:
        if _resolves(candidate):
            return True
    return False


def _resolves(domain: str) -> bool:
    try:
        socket.getaddrinfo(domain, None)
    except socket.gaierror:
        return False
    return True


def analyze_domains(
    credentials: tuple[Credential, ...],
    lookup: DomainLookupFn = domain_exists,
    progress: ProgressFn | None = None,
    max_workers: int = 16,
) -> tuple[Finding, ...]:
    credentials_by_domain: dict[str, list[Credential]] = {}
    for credential in credentials:
        if credential.is_ssh_key:
            continue
        for url in credential.urls:
            domain = extract_domain(url)
            if domain:
                credentials_by_domain.setdefault(domain, []).append(credential)

    if not credentials_by_domain:
        return ()

    exists_by_domain: dict[str, bool] = {}
    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as executor:
        future_to_domain = {
            executor.submit(lookup, domain): domain for domain in credentials_by_domain
        }
        for future in as_completed(future_to_domain):
            domain = future_to_domain[future]
            try:
                exists_by_domain[domain] = future.result()
            except Exception:
                logger.warning("DNS lookup failed for %s, assuming domain exists", domain)
                exists_by_domain[domain] = True
            if progress is not None:
                progress(domain)

    findings: list[Finding] = []
    for domain, exists in sorted(exists_by_domain.items()):
        if exists:
            continue
        affected_ids = tuple(
            credential.id for credential in credentials_by_domain[domain]
        )
        findings.append(
            Finding(
                severity="obsolete",
                category="domain_missing",
                credential_ids=affected_ids,
                explanation=f"The domain {domain} does not resolve in DNS.",
                recommendation="Review these entries; if the service no longer exists, the saved credential is probably obsolete and can be removed after confirmation.",
            )
        )
    return tuple(findings)

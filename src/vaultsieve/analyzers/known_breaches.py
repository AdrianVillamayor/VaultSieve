from __future__ import annotations

import json
import logging
import time
import urllib.request
from collections import defaultdict
from collections.abc import Callable
from pathlib import Path
from typing import Any

from vaultsieve.analyzers.domains import extract_domain
from vaultsieve.config import config_path
from vaultsieve.models import Credential, Finding

logger = logging.getLogger(__name__)

KnownBreachesLookupFn = Callable[[], dict[str, list[dict[str, Any]]]]

HIBP_BREACHES_URL = "https://haveibeenpwned.com/api/v3/breaches"
CACHE_TTL_SECONDS = 7 * 24 * 60 * 60


def known_breaches_cache_path() -> Path:
    return config_path().with_name("hibp-breaches.json")


def load_known_breaches(
    *,
    cache_path: Path | None = None,
    ttl_seconds: int = CACHE_TTL_SECONDS,
) -> dict[str, list[dict[str, Any]]]:
    path = cache_path or known_breaches_cache_path()
    cached = _read_cache(path)
    if cached is not None and _cache_is_fresh(path, ttl_seconds):
        return cached
    try:
        request = urllib.request.Request(
            HIBP_BREACHES_URL,
            headers={"User-Agent": "VaultSieve"},
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        logger.warning("HIBP breach catalogue fetch failed: %s", exc)
        if cached is not None:
            return cached
        raise
    if not isinstance(data, list):
        if cached is not None:
            return cached
        return {}
    _write_cache(path, data)
    return _normalize_breaches(data)


def analyze_known_breaches(
    credentials: tuple[Credential, ...],
    lookup: KnownBreachesLookupFn = load_known_breaches,
) -> tuple[Finding, ...]:
    try:
        breaches_by_domain = lookup()
    except Exception:
        return (
            Finding(
                severity="low",
                category="input_issue",
                credential_ids=(),
                explanation="Have I Been Pwned breach catalogue could not be checked.",
                recommendation="Retry later or disable the known breached services check if the service is unavailable.",
            ),
        )

    credentials_by_domain: dict[str, list[Credential]] = defaultdict(list)
    for credential in credentials:
        if credential.is_ssh_key:
            continue
        for url in credential.urls:
            matched_domain = _matching_domain(extract_domain(url), breaches_by_domain)
            if matched_domain:
                credentials_by_domain[matched_domain].append(credential)

    findings: list[Finding] = []
    for domain, affected_credentials in sorted(credentials_by_domain.items()):
        breaches = breaches_by_domain[domain]
        history = ", ".join(_breach_label(breach) for breach in breaches[:5])
        extra = "" if len(breaches) <= 5 else f", and {len(breaches) - 5} more"
        findings.append(
            Finding(
                severity="low",
                category="service_known_breach",
                credential_ids=tuple(credential.id for credential in affected_credentials),
                explanation=f"The service domain {domain} has public breach history. This does not mean your email or these specific accounts were exposed. Known breach history: {history}{extra}.",
                recommendation="Review these accounts, especially if passwords are old or reused, and enable 2FA where available.",
            )
        )
    return tuple(findings)


def _matching_domain(domain: str, breaches_by_domain: dict[str, list[dict[str, Any]]]) -> str:
    if not domain:
        return ""
    parts = domain.split(".")
    candidates = [domain]
    candidates.extend(".".join(parts[index:]) for index in range(1, max(1, len(parts) - 1)))
    for candidate in candidates:
        if candidate in breaches_by_domain:
            return candidate
    return ""


def _breach_label(breach: dict[str, Any]) -> str:
    title = str(breach.get("Title") or breach.get("Name") or "Unknown breach")
    date = str(breach.get("BreachDate") or "unknown date")
    return f"{title} ({date})"


def _read_cache(path: Path) -> dict[str, list[dict[str, Any]]] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, list):
        return None
    return _normalize_breaches(data)


def _write_cache(path: Path, data: list[dict[str, Any]]) -> None:
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(data, ensure_ascii=False), encoding="utf-8")
    except OSError:
        return


def _cache_is_fresh(path: Path, ttl_seconds: int) -> bool:
    try:
        return time.time() - path.stat().st_mtime < ttl_seconds
    except OSError:
        return False


def _normalize_breaches(data: list[Any]) -> dict[str, list[dict[str, Any]]]:
    breaches_by_domain: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for entry in data:
        if not isinstance(entry, dict):
            continue
        domain = str(entry.get("Domain") or "").strip().lower().removeprefix("www.")
        if domain:
            breaches_by_domain[domain].append(entry)
    return dict(breaches_by_domain)

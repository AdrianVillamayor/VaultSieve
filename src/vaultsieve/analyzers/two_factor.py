from __future__ import annotations

import json
import logging
import time
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

from vaultsieve.analyzers.domains import extract_domain
from vaultsieve.config import config_path
from vaultsieve.models import Credential, Finding

logger = logging.getLogger(__name__)

TwoFactorLookupFn = Callable[[], dict[str, dict[str, Any]]]

TOTP_DIRECTORY_URL = "https://api.2fa.directory/v4/totp.json"
CACHE_TTL_SECONDS = 7 * 24 * 60 * 60


def two_factor_cache_path() -> Path:
    return config_path().with_name("2fa-directory-totp.json")


def load_totp_directory(
    *,
    cache_path: Path | None = None,
    ttl_seconds: int = CACHE_TTL_SECONDS,
) -> dict[str, dict[str, Any]]:
    path = cache_path or two_factor_cache_path()
    cached = _read_cache(path)
    if cached is not None and _cache_is_fresh(path, ttl_seconds):
        return cached
    try:
        request = urllib.request.Request(
            TOTP_DIRECTORY_URL,
            headers={"User-Agent": "VaultSieve"},
        )
        with urllib.request.urlopen(request, timeout=15) as response:
            data = json.loads(response.read().decode("utf-8"))
    except Exception as exc:
        logger.warning("2FA directory fetch failed: %s", exc)
        if cached is not None:
            return cached
        raise
    if not isinstance(data, dict):
        if cached is not None:
            return cached
        return {}
    _write_cache(path, data)
    return _normalize_directory(data)


def analyze_two_factor(
    credentials: tuple[Credential, ...],
    lookup: TwoFactorLookupFn = load_totp_directory,
) -> tuple[Finding, ...]:
    try:
        directory = lookup()
    except Exception:
        return (
            Finding(
                severity="low",
                category="input_issue",
                credential_ids=(),
                explanation="2FA Directory could not be checked.",
                recommendation="Retry later or disable the 2FA availability check if the service is unavailable.",
            ),
        )

    findings: list[Finding] = []
    for credential in credentials:
        if credential.is_ssh_key or credential.has_totp or credential.has_passkey:
            continue
        matched_entry = _match_directory_entry(credential, directory)
        if matched_entry is None:
            continue
        recommendation = "Confirm 2FA is enabled for this account. If you use a separate authenticator app or hardware key, no vault change may be needed."
        documentation = matched_entry.get("documentation")
        if isinstance(documentation, str) and documentation:
            recommendation = f"{recommendation} Setup documentation: {documentation}"
        findings.append(
            Finding(
                severity="medium",
                category="two_factor_not_stored",
                credential_ids=(credential.id,),
                explanation=_two_factor_explanation(credential),
                recommendation=recommendation,
            )
        )
    return tuple(findings)


def _two_factor_explanation(credential: Credential) -> str:
    if credential.source == "csv":
        return "This service supports TOTP-based 2FA, but this CSV export does not represent a stored TOTP secret."
    return "This service supports TOTP-based 2FA, but this vault entry does not include a stored TOTP secret."


def _match_directory_entry(
    credential: Credential,
    directory: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    for url in credential.urls:
        domain = extract_domain(url)
        if not domain:
            continue
        parts = domain.split(".")
        candidates = [".".join(parts[index:]) for index in range(max(0, len(parts) - 2), len(parts))]
        candidates.insert(0, domain)
        for candidate in candidates:
            entry = directory.get(candidate)
            if entry is not None:
                return entry
    return None


def _read_cache(path: Path) -> dict[str, dict[str, Any]] | None:
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return _normalize_directory(data)


def _write_cache(path: Path, data: dict[str, Any]) -> None:
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


def _normalize_directory(data: dict[str, Any]) -> dict[str, dict[str, Any]]:
    return {
        str(domain).lower().removeprefix("www."): entry
        for domain, entry in data.items()
        if isinstance(entry, dict)
    }

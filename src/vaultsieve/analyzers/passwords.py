from __future__ import annotations

from urllib.parse import urlparse

from vaultsieve.models import Credential, Finding, normalize


def _is_low_complexity(password: str) -> bool:
    classes = 0
    classes += any(char.islower() for char in password)
    classes += any(char.isupper() for char in password)
    classes += any(char.isdigit() for char in password)
    classes += any(not char.isalnum() for char in password)
    return classes < 3


def _is_similar(password: str, *values: str) -> bool:
    normalized_password = normalize(password)
    if len(normalized_password) < 4:
        return False
    for value in values:
        normalized_value = normalize(value)
        if len(normalized_value) >= 4 and normalized_value in normalized_password:
            return True
    return False


def _has_only_app_urls(credential: Credential) -> bool:
    if not credential.urls:
        return False
    for url in credential.urls:
        scheme = urlparse(url.strip()).scheme.lower()
        if scheme in {"", "http", "https"}:
            return False
    return True


def analyze_password_quality(
    credentials: tuple[Credential, ...],
    *,
    min_length: int = 12,
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    for credential in credentials:
        if credential.is_ssh_key:
            continue
        password = credential.password
        if not password:
            if credential.has_passkey or _has_only_app_urls(credential):
                continue
            findings.append(
                Finding(
                    severity="critical",
                    category="empty",
                    credential_ids=(credential.id,),
                    explanation="This entry has an empty password.",
                    recommendation="Set a strong unique password for this account.",
                )
            )
            continue

        if len(password) < min_length:
            findings.append(
                Finding(
                    severity="medium",
                    category="weak",
                    credential_ids=(credential.id,),
                    explanation=f"This password is shorter than {min_length} characters.",
                    recommendation="Replace it with a longer unique password.",
                )
            )

        if _is_low_complexity(password):
            findings.append(
                Finding(
                    severity="medium",
                    category="weak",
                    credential_ids=(credential.id,),
                    explanation="This password uses too few character classes.",
                    recommendation="Use a generated password with mixed character classes.",
                )
            )

        if _is_similar(password, credential.name, credential.username):
            findings.append(
                Finding(
                    severity="medium",
                    category="similar",
                    credential_ids=(credential.id,),
                    explanation="This password appears similar to the entry name or username.",
                    recommendation="Avoid passwords based on account names or usernames.",
                )
            )
    return tuple(findings)

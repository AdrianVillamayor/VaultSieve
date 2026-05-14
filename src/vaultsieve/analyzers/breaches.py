from __future__ import annotations

import hashlib
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed

from vaultsieve.models import Credential, Finding

LookupFn = Callable[[str], str]
ProgressFn = Callable[[str], None]


def hibp_lookup(prefix: str) -> str:
    request = urllib.request.Request(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"User-Agent": "VaultSieve", "Add-Padding": "true"},
    )
    with urllib.request.urlopen(request, timeout=10) as response:  # nosec: opt-in API call
        return response.read().decode("utf-8")


def is_password_breached(password: str, lookup: LookupFn = hibp_lookup) -> bool:
    digest = hashlib.sha1(password.encode("utf-8")).hexdigest().upper()
    prefix = digest[:5]
    suffix = digest[5:]
    response_text = lookup(prefix)
    for line in response_text.splitlines():
        returned_suffix, _, count = line.partition(":")
        if count.strip() == "0":
            continue
        returned_suffix = returned_suffix.strip().upper()
        if returned_suffix == suffix:
            return True
    return False


def analyze_breaches(
    credentials: tuple[Credential, ...],
    lookup: LookupFn = hibp_lookup,
    progress: ProgressFn | None = None,
    max_workers: int = 4,
) -> tuple[Finding, ...]:
    findings: list[Finding] = []
    credentials_by_password: dict[str, list[Credential]] = {}
    for credential in credentials:
        if credential.is_ssh_key:
            continue
        if credential.password:
            credentials_by_password.setdefault(credential.password, []).append(credential)

    if not credentials_by_password:
        return ()

    worker_count = max(1, max_workers)
    breached_by_password: dict[str, bool] = {}
    with ThreadPoolExecutor(max_workers=worker_count) as executor:
        future_to_password = {
            executor.submit(is_password_breached, password, lookup): password
            for password in credentials_by_password
        }
        for future in as_completed(future_to_password):
            password = future_to_password[future]
            try:
                breached_by_password[password] = future.result()
            except Exception:
                for credential in credentials_by_password[password]:
                    findings.append(
                        Finding(
                            severity="low",
                            category="input_issue",
                            credential_ids=(credential.id,),
                            explanation="Have I Been Pwned could not be checked for this password.",
                            recommendation="Retry later or run without breach checking if the service is unavailable.",
                        )
                    )
                breached_by_password[password] = False
            if progress is not None:
                progress(password)

    for password, breached in breached_by_password.items():
        if not breached:
            continue
        for credential in credentials_by_password[password]:
            findings.append(
                Finding(
                    severity="critical",
                    category="breached",
                    credential_ids=(credential.id,),
                    explanation="This password appears in known breach data.",
                    recommendation="Change this password immediately and do not reuse it elsewhere.",
                )
            )
    return tuple(findings)

from __future__ import annotations

import logging
import urllib.error
import urllib.request
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor, as_completed
from urllib.parse import urlparse

from vaultsieve.models import Credential, Finding

logger = logging.getLogger(__name__)

HttpRedirectCheckFn = Callable[[str], bool]


def redirects_to_https(url: str) -> bool:
    request = urllib.request.Request(url, method="HEAD", headers={"User-Agent": "VaultSieve"})
    try:
        with urllib.request.urlopen(request, timeout=2) as response:
            final_url = response.geturl()
    except urllib.error.HTTPError as err:
        final_url = err.geturl()
    except Exception:
        logger.warning("HTTP redirect check failed for %s", url)
        return False
    return urlparse(final_url).scheme.lower() == "https"


def analyze_insecure_http(
    credentials: tuple[Credential, ...],
    redirect_check: HttpRedirectCheckFn = redirects_to_https,
    max_workers: int = 32,
) -> tuple[Finding, ...]:
    http_urls = sorted(
        {
            url
            for credential in credentials
            if not credential.is_ssh_key
            for url in credential.urls
            if _is_insecure_http(url)
        }
    )
    redirects_by_url = _check_redirects(http_urls, redirect_check, max_workers)

    findings: list[Finding] = []
    for credential in credentials:
        if credential.is_ssh_key:
            continue
        insecure_urls = tuple(
            url
            for url in credential.urls
            if _is_insecure_http(url) and not redirects_by_url.get(url, False)
        )
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


def _check_redirects(
    urls: list[str],
    redirect_check: HttpRedirectCheckFn,
    max_workers: int,
) -> dict[str, bool]:
    if not urls:
        return {}
    redirects: dict[str, bool] = {}
    with ThreadPoolExecutor(max_workers=max(1, max_workers)) as executor:
        future_to_url = {executor.submit(redirect_check, url): url for url in urls}
        for future in as_completed(future_to_url):
            url = future_to_url[future]
            try:
                redirects[url] = future.result()
            except Exception:
                logger.warning("Redirect check failed for %s", url)
                redirects[url] = False
    return redirects


def _is_insecure_http(url: str) -> bool:
    candidate = url.strip()
    if not candidate or "://" not in candidate:
        return False
    parsed = urlparse(candidate)
    return parsed.scheme.lower() == "http"

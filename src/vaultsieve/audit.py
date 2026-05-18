from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from vaultsieve.analyzers.breaches import LookupFn, analyze_breaches
from vaultsieve.analyzers.domain_concentration import analyze_domain_concentration
from vaultsieve.analyzers.domains import DomainLookupFn, analyze_domains, extract_domain
from vaultsieve.analyzers.duplicates import analyze_duplicates
from vaultsieve.analyzers.insecure_http import analyze_insecure_http
from vaultsieve.analyzers.known_breaches import KnownBreachesLookupFn, analyze_known_breaches
from vaultsieve.analyzers.passwords import analyze_password_quality
from vaultsieve.analyzers.two_factor import TwoFactorLookupFn, analyze_two_factor
from vaultsieve.importers.bitwarden import import_bitwarden
from vaultsieve.importers.csv_generic import import_csv
from vaultsieve.models import (
    SEVERITY_ORDER,
    AuditOptions,
    AuditReport,
    Credential,
    Finding,
    InputFormat,
)

ProgressCallback = Callable[[str, int | None], None]


def import_credentials(input_path: Path, input_format: InputFormat) -> tuple[Credential, ...]:
    if input_format == "bitwarden":
        return import_bitwarden(input_path)
    if input_format == "csv":
        return import_csv(input_path)
    raise ValueError(f"Unsupported input format: {input_format}")


def run_audit(
    input_path: Path,
    input_format: InputFormat,
    options: AuditOptions | None = None,
    *,
    breach_lookup: LookupFn | None = None,
    domain_lookup: DomainLookupFn | None = None,
    two_factor_lookup: TwoFactorLookupFn | None = None,
    known_breaches_lookup: KnownBreachesLookupFn | None = None,
    progress: ProgressCallback | None = None,
) -> AuditReport:
    audit_options = options or AuditOptions()
    if progress is not None:
        progress("Importing credentials", None)
    credentials = import_credentials(input_path, input_format)
    findings: list[Finding] = []

    if progress is not None:
        progress("Analyzing exact duplicates and reused passwords", None)
    findings.extend(analyze_duplicates(credentials))

    if progress is not None:
        progress("Checking password quality", None)
    findings.extend(
        analyze_password_quality(
            credentials,
            min_length=audit_options.min_password_length,
        )
    )

    if progress is not None:
        progress("Checking insecure website URLs", None)
    findings.extend(analyze_insecure_http(credentials))

    if progress is not None:
        progress("Checking domains with many saved accounts", None)
    findings.extend(analyze_domain_concentration(credentials))

    if audit_options.check_breaches:
        total = len({credential.password for credential in credentials if credential.password})
        checked = 0

        def breach_progress(_password: str) -> None:
            nonlocal checked
            checked += 1
            if progress is not None:
                progress(
                    f"Checking Have I Been Pwned ({checked}/{total} unique passwords)",
                    checked if total else None,
                )

        if progress is not None:
            progress(f"Checking Have I Been Pwned (0/{total} unique passwords)", 0)
        if breach_lookup is None:
            findings.extend(
                analyze_breaches(
                    credentials,
                    progress=breach_progress,
                    max_workers=audit_options.hibp_workers,
                )
            )
        else:
            findings.extend(
                analyze_breaches(
                    credentials,
                    breach_lookup,
                    breach_progress,
                    audit_options.hibp_workers,
                )
            )

    if audit_options.check_domains:
        domains = {
            d
            for credential in credentials
            for url in credential.urls
            if (d := extract_domain(url))
        }
        total = len(domains)
        checked = 0

        def domain_progress(_domain: str) -> None:
            nonlocal checked
            checked += 1
            if progress is not None:
                progress(
                    f"Checking credential domains ({checked}/{total} unique domains)",
                    checked if total else None,
                )

        if progress is not None:
            progress(f"Checking credential domains (0/{total} unique domains)", 0)
        if domain_lookup is None:
            findings.extend(
                analyze_domains(
                    credentials,
                    progress=domain_progress,
                    max_workers=audit_options.domain_workers,
                )
            )
        else:
            findings.extend(
                analyze_domains(
                    credentials,
                    domain_lookup,
                    domain_progress,
                    audit_options.domain_workers,
                )
            )

    if audit_options.check_2fa:
        if progress is not None:
            progress("Checking 2FA availability", None)
        if two_factor_lookup is None:
            findings.extend(analyze_two_factor(credentials))
        else:
            findings.extend(analyze_two_factor(credentials, two_factor_lookup))

    if audit_options.check_known_breaches:
        if progress is not None:
            progress("Checking known breached services", None)
        if known_breaches_lookup is None:
            findings.extend(analyze_known_breaches(credentials))
        else:
            findings.extend(analyze_known_breaches(credentials, known_breaches_lookup))

    if progress is not None:
        progress("Preparing report", None)
    findings.sort(key=lambda finding: SEVERITY_ORDER[finding.severity])
    return AuditReport(
        input_path=input_path,
        input_format=input_format,
        credentials=credentials,
        findings=tuple(findings),
    )

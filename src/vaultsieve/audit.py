from __future__ import annotations

from pathlib import Path
from collections.abc import Callable

from vaultsieve.analyzers.breaches import LookupFn, analyze_breaches
from vaultsieve.analyzers.duplicates import analyze_duplicates
from vaultsieve.analyzers.passwords import analyze_password_quality
from vaultsieve.importers.bitwarden import import_bitwarden
from vaultsieve.importers.csv_generic import import_csv
from vaultsieve.models import AuditOptions, AuditReport, Credential, Finding, InputFormat, SEVERITY_ORDER

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

    if progress is not None:
        progress("Preparing report", None)
    findings.sort(key=lambda finding: SEVERITY_ORDER[finding.severity])
    return AuditReport(
        input_path=input_path,
        input_format=input_format,
        credentials=credentials,
        findings=tuple(findings),
    )

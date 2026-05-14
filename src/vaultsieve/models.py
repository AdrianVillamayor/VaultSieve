from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal

Severity = Literal["critical", "high", "medium", "low", "obsolete"]
FindingCategory = Literal[
    "duplicate",
    "reuse",
    "weak",
    "empty",
    "similar",
    "breached",
    "domain_missing",
    "input_issue",
]
InputFormat = Literal["bitwarden", "csv"]

SEVERITY_ORDER: dict[Severity, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "obsolete": 4,
}


@dataclass(frozen=True)
class Credential:
    id: str
    source: InputFormat
    source_index: int
    name: str
    username: str
    password: str
    urls: tuple[str, ...] = ()
    has_passkey: bool = False
    is_ssh_key: bool = False
    raw: dict[str, Any] | None = None

    def safe_reference(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "source": self.source,
            "source_index": self.source_index,
            "name": self.name,
            "username": self.username,
            "urls": list(self.urls),
            "has_passkey": self.has_passkey,
            "is_ssh_key": self.is_ssh_key,
        }


@dataclass(frozen=True)
class Finding:
    severity: Severity
    category: FindingCategory
    credential_ids: tuple[str, ...]
    explanation: str
    recommendation: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "severity": self.severity,
            "category": self.category,
            "credential_ids": list(self.credential_ids),
            "explanation": self.explanation,
            "recommendation": self.recommendation,
        }


@dataclass(frozen=True)
class AuditOptions:
    check_breaches: bool = False
    check_domains: bool = False
    hibp_workers: int = 4
    domain_workers: int = 16
    min_password_length: int = 12


@dataclass(frozen=True)
class AuditReport:
    input_path: Path
    input_format: InputFormat
    credentials: tuple[Credential, ...]
    findings: tuple[Finding, ...] = field(default_factory=tuple)

    @property
    def summary_by_severity(self) -> dict[Severity, int]:
        summary: dict[Severity, int] = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "obsolete": 0,
        }
        for finding in self.findings:
            summary[finding.severity] += 1
        return summary

    def credential_map(self) -> dict[str, Credential]:
        return {credential.id: credential for credential in self.credentials}

    def to_safe_dict(self) -> dict[str, Any]:
        return {
            "input_path": str(self.input_path),
            "input_format": self.input_format,
            "credential_count": len(self.credentials),
            "summary_by_severity": self.summary_by_severity,
            "credentials": [credential.safe_reference() for credential in self.credentials],
            "findings": [finding.to_dict() for finding in self.findings],
        }


def normalize(value: object) -> str:
    if value is None:
        return ""
    return str(value).strip().lower()

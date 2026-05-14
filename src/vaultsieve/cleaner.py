from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Literal

from vaultsieve.analyzers.duplicates import duplicate_removal_ids
from vaultsieve.errors import VaultSieveError
from vaultsieve.importers.bitwarden import load_bitwarden_data
from vaultsieve.models import Credential, Finding, InputFormat

CleanMode = Literal["duplicates", "obsolete", "all"]


def write_clean_output(
    input_path: Path,
    output_path: Path,
    input_format: InputFormat,
    credentials: tuple[Credential, ...],
    findings: tuple[Finding, ...] = (),
    mode: CleanMode = "duplicates",
    duplicate_remove_ids: set[str] | None = None,
) -> int:
    remove_ids = removal_ids(credentials, findings, mode, duplicate_remove_ids)
    if output_path.exists() and output_path.is_dir():
        raise VaultSieveError(
            f"Clean output must be a file path, not a directory: {output_path}"
        )
    try:
        output_path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as err:
        raise VaultSieveError(f"Cannot create output directory: {output_path.parent}") from err
    if input_format == "bitwarden":
        return _write_clean_bitwarden(input_path, output_path, credentials, remove_ids)
    if input_format == "csv":
        return _write_clean_csv(output_path, credentials, remove_ids)
    raise ValueError(f"Unsupported input format: {input_format}")


def removal_ids(
    credentials: tuple[Credential, ...],
    findings: tuple[Finding, ...] = (),
    mode: CleanMode = "duplicates",
    duplicate_remove_ids: set[str] | None = None,
) -> set[str]:
    if mode not in {"duplicates", "obsolete", "all"}:
        raise VaultSieveError(f"Unsupported clean mode: {mode}")

    remove: set[str] = set()
    if mode in {"duplicates", "all"}:
        if duplicate_remove_ids is None:
            remove.update(duplicate_removal_ids(credentials))
        else:
            known_ids = {credential.id for credential in credentials}
            remove.update(credential_id for credential_id in duplicate_remove_ids if credential_id in known_ids)
    if mode in {"obsolete", "all"}:
        for finding in findings:
            if finding.category == "domain_missing":
                remove.update(finding.credential_ids)
    return remove


def _write_clean_bitwarden(
    input_path: Path,
    output_path: Path,
    credentials: tuple[Credential, ...],
    remove_ids: set[str],
) -> int:
    data = load_bitwarden_data(input_path)
    remove_indexes = {
        credential.source_index for credential in credentials if credential.id in remove_ids
    }
    data["items"] = [
        item for index, item in enumerate(data["items"]) if index not in remove_indexes
    ]
    try:
        with output_path.open("w", encoding="utf-8") as file:
            json.dump(data, file, ensure_ascii=False, indent=2)
    except OSError as err:
        raise VaultSieveError(f"Cannot write clean output: {output_path}") from err
    return len(remove_indexes)


def _write_clean_csv(
    output_path: Path,
    credentials: tuple[Credential, ...],
    remove_ids: set[str],
) -> int:
    rows = [credential for credential in credentials if credential.id not in remove_ids]
    try:
        with output_path.open("w", encoding="utf-8", newline="") as file:
            writer = csv.DictWriter(file, fieldnames=["name", "url", "username", "password"])
            writer.writeheader()
            for credential in rows:
                writer.writerow(
                    {
                        "name": credential.name,
                        "url": credential.urls[0] if credential.urls else "",
                        "username": credential.username,
                        "password": credential.password,
                    }
                )
    except OSError as err:
        raise VaultSieveError(f"Cannot write clean output: {output_path}") from err
    return len(remove_ids)

from __future__ import annotations

import csv
from dataclasses import dataclass
from pathlib import Path

from vaultsieve.errors import VaultSieveError
from vaultsieve.models import Credential, InputFormat


@dataclass(frozen=True)
class ColumnMap:
    name: str
    url: str
    username: str
    password: str
    note: str | None = None
    totp: str | None = None
    folder: str | None = None


def import_mapped_csv(
    path: Path,
    source: InputFormat,
    columns: ColumnMap,
    *,
    required: tuple[str, ...] | None = None,
    encoding: str = "utf-8",
    strip_bom: bool = False,
) -> tuple[Credential, ...]:
    effective_encoding = "utf-8-sig" if strip_bom else encoding
    try:
        with path.open("r", encoding=effective_encoding, newline="") as file:
            reader = csv.DictReader(file)
            fieldnames = set(reader.fieldnames or [])

            check_cols = (
                set(required)
                if required
                else {columns.name, columns.url, columns.username, columns.password}
            )
            missing = check_cols - fieldnames
            if missing:
                raise VaultSieveError(
                    f"{source} CSV is missing required columns: {', '.join(sorted(missing))}"
                )

            credentials: list[Credential] = []
            for index, row in enumerate(reader):
                url = (row.get(columns.url) or "").strip()
                totp_value = ""
                if columns.totp:
                    totp_value = (row.get(columns.totp) or "").strip()
                credentials.append(
                    Credential(
                        id=f"{source}:{index}",
                        source=source,
                        source_index=index,
                        name=row.get(columns.name) or "",
                        username=row.get(columns.username) or "",
                        password=row.get(columns.password) or "",
                        urls=(url,) if url else (),
                        has_totp=bool(totp_value),
                        raw=dict(row),
                    )
                )
    except FileNotFoundError as err:
        raise VaultSieveError(f"Input file does not exist: {path}") from err
    except PermissionError as err:
        raise VaultSieveError(f"Cannot read input file: {path}") from err
    except csv.Error as err:
        raise VaultSieveError(f"Invalid {source} CSV file: {err}") from err
    return tuple(credentials)


def write_clean_mapped_csv(
    input_path: Path,
    output_path: Path,
    credentials: tuple[Credential, ...],
    remove_ids: set[str],
    *,
    encoding: str = "utf-8",
    strip_bom: bool = False,
) -> int:
    remove_indexes = {
        credential.source_index for credential in credentials if credential.id in remove_ids
    }
    effective_encoding = "utf-8-sig" if strip_bom else encoding
    try:
        with input_path.open("r", encoding=effective_encoding, newline="") as infile:
            reader = csv.DictReader(infile)
            fieldnames = reader.fieldnames or []
            rows = [(index, row) for index, row in enumerate(reader)]

        with output_path.open("w", encoding="utf-8", newline="") as outfile:
            writer = csv.DictWriter(outfile, fieldnames=fieldnames)
            writer.writeheader()
            for index, row in rows:
                if index not in remove_indexes:
                    writer.writerow(row)
    except FileNotFoundError as err:
        raise VaultSieveError(f"Input file does not exist: {input_path}") from err
    except OSError as err:
        raise VaultSieveError(f"Cannot write clean output: {output_path}") from err
    return len(remove_indexes)

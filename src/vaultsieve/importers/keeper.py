from __future__ import annotations

import csv
from pathlib import Path

from vaultsieve.errors import VaultSieveError
from vaultsieve.importers._csv_base import ColumnMap, import_mapped_csv
from vaultsieve.models import Credential

COLUMNS = ColumnMap(
    name="Title",
    url="Website Address",
    username="Login",
    password="Password",
    note="Notes",
    totp="TOTP",
    folder="Folder",
)

HEADERLESS_FIELDS = ("Folder", "Title", "Login", "Password", "Website Address", "Notes", "TOTP")


def import_keeper(path: Path) -> tuple[Credential, ...]:
    if _has_headers(path):
        return import_mapped_csv(
            path,
            "keeper",
            COLUMNS,
            required=("Title", "Login", "Password"),
        )
    return _import_headerless(path)


def _has_headers(path: Path) -> bool:
    try:
        with path.open("r", encoding="utf-8", newline="") as file:
            first_line = file.readline().strip().strip('"')
            return first_line.lower().startswith("folder") and "title" in first_line.lower()
    except OSError:
        return False


def _import_headerless(path: Path) -> tuple[Credential, ...]:
    try:
        with path.open("r", encoding="utf-8", newline="") as file:
            reader = csv.reader(file)
            credentials: list[Credential] = []
            for index, row in enumerate(reader):
                if not row or all(cell.strip() == "" for cell in row):
                    continue
                while len(row) < len(HEADERLESS_FIELDS):
                    row.append("")
                raw = dict(zip(HEADERLESS_FIELDS, row))
                url = raw.get("Website Address", "").strip()
                totp = raw.get("TOTP", "").strip()
                credentials.append(
                    Credential(
                        id=f"keeper:{index}",
                        source="keeper",
                        source_index=index,
                        name=raw.get("Title", ""),
                        username=raw.get("Login", ""),
                        password=raw.get("Password", ""),
                        urls=(url,) if url else (),
                        has_totp=bool(totp),
                        raw=raw,
                    )
                )
    except FileNotFoundError as err:
        raise VaultSieveError(f"Input file does not exist: {path}") from err
    except PermissionError as err:
        raise VaultSieveError(f"Cannot read input file: {path}") from err
    except csv.Error as err:
        raise VaultSieveError(f"Invalid Keeper CSV: {err}") from err
    return tuple(credentials)

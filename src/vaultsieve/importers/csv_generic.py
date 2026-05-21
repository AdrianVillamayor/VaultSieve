from __future__ import annotations

import csv
from pathlib import Path

from vaultsieve.errors import VaultSieveError
from vaultsieve.models import Credential

REQUIRED_COLUMNS = {"name", "url", "username", "password"}


def import_csv(path: Path) -> tuple[Credential, ...]:
    try:
        with path.open("r", encoding="utf-8", newline="") as file:
            reader = csv.DictReader(file)
            fieldnames = set(reader.fieldnames or [])
            missing = REQUIRED_COLUMNS - fieldnames
            if missing:
                missing_text = ", ".join(sorted(missing))
                raise VaultSieveError(f"CSV is missing required columns: {missing_text}")

            credentials: list[Credential] = []
            for row_index, row in enumerate(reader):
                url = (row.get("url") or "").strip()
                credentials.append(
                    Credential(
                        id=f"csv:{row_index}",
                        source="csv",
                        source_index=row_index,
                        name=row.get("name") or "",
                        username=row.get("username") or "",
                        password=row.get("password") or "",
                        urls=(url,) if url else (),
                        raw=dict(row),
                    )
                )
    except FileNotFoundError as err:
        raise VaultSieveError(f"Input file does not exist: {path}") from err
    except PermissionError as err:
        raise VaultSieveError(f"Cannot read input file: {path}") from err
    except csv.Error as err:
        raise VaultSieveError(f"Invalid CSV file: {err}") from err
    return tuple(credentials)

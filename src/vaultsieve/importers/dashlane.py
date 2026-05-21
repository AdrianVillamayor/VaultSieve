from __future__ import annotations

import tempfile
import zipfile
from pathlib import Path

from vaultsieve.errors import VaultSieveError
from vaultsieve.importers._csv_base import ColumnMap, import_mapped_csv
from vaultsieve.models import Credential

COLUMNS = ColumnMap(
    name="title",
    url="url",
    username="username",
    password="password",
    note="note",
    totp="otpUrl",
    folder="category",
)


def import_dashlane(path: Path) -> tuple[Credential, ...]:
    ext = path.suffix.lower()
    if ext == ".zip":
        return _import_from_zip(path)
    return import_mapped_csv(
        path,
        "dashlane",
        COLUMNS,
        required=("title", "username", "password", "url"),
    )


def _import_from_zip(path: Path) -> tuple[Credential, ...]:
    try:
        with zipfile.ZipFile(path) as zf:
            if "credentials.csv" not in zf.namelist():
                raise VaultSieveError(
                    "Dashlane zip does not contain credentials.csv"
                )
            csv_bytes = zf.read("credentials.csv")
    except FileNotFoundError as err:
        raise VaultSieveError(f"Input file does not exist: {path}") from err
    except zipfile.BadZipFile as err:
        raise VaultSieveError(f"Invalid Dashlane zip: {err}") from err

    with tempfile.NamedTemporaryFile(suffix=".csv", delete=False) as tmp:
        tmp.write(csv_bytes)
        tmp_path = Path(tmp.name)
    try:
        return import_mapped_csv(
            tmp_path,
            "dashlane",
            COLUMNS,
            required=("title", "username", "password", "url"),
        )
    finally:
        tmp_path.unlink(missing_ok=True)

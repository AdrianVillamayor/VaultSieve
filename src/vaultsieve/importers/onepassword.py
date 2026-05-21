from __future__ import annotations

from pathlib import Path

from vaultsieve.importers._csv_base import ColumnMap, import_mapped_csv
from vaultsieve.models import Credential

COLUMNS = ColumnMap(
    name="Title",
    url="Url",
    username="Username",
    password="Password",
    note="Notes",
    totp="OTPAuth",
)


def import_onepassword(path: Path) -> tuple[Credential, ...]:
    return import_mapped_csv(
        path,
        "1password",
        COLUMNS,
        required=("Title", "Username", "Password"),
    )

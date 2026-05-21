from __future__ import annotations

from pathlib import Path

from vaultsieve.importers._csv_base import ColumnMap, import_mapped_csv
from vaultsieve.models import Credential

COLUMNS = ColumnMap(
    name="Title",
    url="URL",
    username="Username",
    password="Password",
    note="Notes",
    totp="TOTP",
    folder="Group",
)


def import_keepass(path: Path) -> tuple[Credential, ...]:
    return import_mapped_csv(
        path,
        "keepass",
        COLUMNS,
        required=("Title", "Username", "Password", "URL"),
    )

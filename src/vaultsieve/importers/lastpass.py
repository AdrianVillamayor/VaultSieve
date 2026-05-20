from __future__ import annotations

from pathlib import Path

from vaultsieve.importers._csv_base import ColumnMap, import_mapped_csv
from vaultsieve.models import Credential

COLUMNS = ColumnMap(
    name="name",
    url="url",
    username="username",
    password="password",
    note="extra",
    totp="totp",
    folder="grouping",
)


def import_lastpass(path: Path) -> tuple[Credential, ...]:
    return import_mapped_csv(
        path,
        "lastpass",
        COLUMNS,
        required=("url", "username", "password", "name"),
    )

from __future__ import annotations

from pathlib import Path

from vaultsieve.importers._csv_base import ColumnMap, import_mapped_csv
from vaultsieve.models import Credential

COLUMNS = ColumnMap(
    name="Name",
    url="Url",
    username="Login",
    password="Pwd",
    note="Note",
    folder="Folder",
)


def import_roboform(path: Path) -> tuple[Credential, ...]:
    return import_mapped_csv(
        path,
        "roboform",
        COLUMNS,
        required=("Name", "Url", "Login", "Pwd"),
        strip_bom=True,
    )

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vaultsieve.errors import VaultSieveError
from vaultsieve.models import Credential


def import_keeper_json(path: Path) -> tuple[Credential, ...]:
    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError as err:
        raise VaultSieveError(f"Input file does not exist: {path}") from err
    except PermissionError as err:
        raise VaultSieveError(f"Cannot read input file: {path}") from err
    except json.JSONDecodeError as err:
        raise VaultSieveError(f"Invalid Keeper JSON: {err}") from err

    records = _extract_records(data)

    credentials: list[Credential] = []
    for index, record in enumerate(records):
        if not isinstance(record, dict):
            continue
        url = str(record.get("login_url") or record.get("url") or "").strip()
        totp = str(record.get("totp") or "").strip()
        credentials.append(
            Credential(
                id=f"keeper:{index}",
                source="keeper",
                source_index=index,
                name=str(record.get("title") or ""),
                username=str(record.get("login") or record.get("username") or ""),
                password=str(record.get("password") or ""),
                urls=(url,) if url else (),
                has_totp=bool(totp),
                raw=record,
            )
        )
    return tuple(credentials)


def load_keeper_json_data(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError as err:
        raise VaultSieveError(f"Input file does not exist: {path}") from err
    except PermissionError as err:
        raise VaultSieveError(f"Cannot read input file: {path}") from err
    except json.JSONDecodeError as err:
        raise VaultSieveError(f"Invalid Keeper JSON: {err}") from err
    return data


def _extract_records(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        if "records" in data:
            records = data["records"]
            if isinstance(records, list):
                return records
    raise VaultSieveError("Keeper JSON must contain a 'records' list.")

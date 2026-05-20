from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vaultsieve.errors import VaultSieveError
from vaultsieve.models import Credential


def import_dashlane_json(path: Path) -> tuple[Credential, ...]:
    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError as err:
        raise VaultSieveError(f"Input file does not exist: {path}") from err
    except PermissionError as err:
        raise VaultSieveError(f"Cannot read input file: {path}") from err
    except json.JSONDecodeError as err:
        raise VaultSieveError(f"Invalid Dashlane JSON: {err}") from err

    items = _extract_items(data)

    credentials: list[Credential] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        url = str(item.get("domain") or item.get("url") or "").strip()
        if url and not url.startswith(("http://", "https://")):
            url = f"https://{url}"
        otp = str(item.get("otpSecret") or item.get("otpUrl") or "").strip()
        credentials.append(
            Credential(
                id=f"dashlane:{index}",
                source="dashlane",
                source_index=index,
                name=str(item.get("title") or item.get("name") or ""),
                username=str(item.get("login") or item.get("email") or ""),
                password=str(item.get("password") or ""),
                urls=(url,) if url else (),
                has_totp=bool(otp),
                raw=item,
            )
        )
    return tuple(credentials)


def load_dashlane_json_data(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError as err:
        raise VaultSieveError(f"Input file does not exist: {path}") from err
    except PermissionError as err:
        raise VaultSieveError(f"Cannot read input file: {path}") from err
    except json.JSONDecodeError as err:
        raise VaultSieveError(f"Invalid Dashlane JSON: {err}") from err
    return data


def _extract_items(data: Any) -> list[dict[str, Any]]:
    if isinstance(data, dict):
        if "AUTHENTIFIANT" in data:
            items = data["AUTHENTIFIANT"]
            if isinstance(items, list):
                return items
        if "items" in data:
            items = data["items"]
            if isinstance(items, list):
                return items
    raise VaultSieveError(
        "Dashlane JSON must contain an 'AUTHENTIFIANT' or 'items' list."
    )

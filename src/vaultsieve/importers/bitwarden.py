from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vaultsieve.errors import VaultSieveError
from vaultsieve.models import Credential, normalize


def extract_uris(item: dict[str, Any]) -> tuple[str, ...]:
    login = item.get("login") or {}
    uris = login.get("uris") or []
    result: list[str] = []
    for uri_entry in uris:
        if isinstance(uri_entry, dict):
            uri = normalize(uri_entry.get("uri"))
            if uri:
                result.append(uri)
    return tuple(sorted(result))


def has_passkey(item: dict[str, Any]) -> bool:
    login = item.get("login") or {}
    return bool(login.get("fido2Credentials"))


def has_totp(item: dict[str, Any]) -> bool:
    login = item.get("login") or {}
    return bool(str(login.get("totp") or "").strip())


def is_ssh_key(item: dict[str, Any]) -> bool:
    return item.get("type") == 5 or bool(item.get("sshKey"))


def import_bitwarden(path: Path) -> tuple[Credential, ...]:
    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError as err:
        raise VaultSieveError(f"Input file does not exist: {path}") from err
    except PermissionError as err:
        raise VaultSieveError(f"Cannot read input file: {path}") from err
    except json.JSONDecodeError as err:
        raise VaultSieveError(f"Invalid Bitwarden JSON: {err}") from err

    items = data.get("items") if isinstance(data, dict) else None
    if not isinstance(items, list):
        raise VaultSieveError("Bitwarden JSON must contain an 'items' list.")

    credentials: list[Credential] = []
    for index, item in enumerate(items):
        if not isinstance(item, dict) or item.get("type") not in {1, 5}:
            continue
        login = item.get("login") or {}
        credentials.append(
            Credential(
                id=f"bitwarden:{index}",
                source="bitwarden",
                source_index=index,
                name=str(item.get("name") or ""),
                username=str(login.get("username") or ""),
                password=str(login.get("password") or ""),
                urls=extract_uris(item),
                has_passkey=has_passkey(item),
                has_totp=has_totp(item),
                is_ssh_key=is_ssh_key(item),
                raw=item,
            )
        )
    return tuple(credentials)


def load_bitwarden_data(path: Path) -> dict[str, Any]:
    try:
        with path.open("r", encoding="utf-8") as file:
            data = json.load(file)
    except FileNotFoundError as err:
        raise VaultSieveError(f"Input file does not exist: {path}") from err
    except PermissionError as err:
        raise VaultSieveError(f"Cannot read input file: {path}") from err
    except json.JSONDecodeError as err:
        raise VaultSieveError(f"Invalid Bitwarden JSON: {err}") from err
    if not isinstance(data, dict) or not isinstance(data.get("items"), list):
        raise VaultSieveError("Bitwarden JSON must contain an 'items' list.")
    return data

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

from vaultsieve.errors import VaultSieveError
from vaultsieve.models import Credential


def import_onepassword_1pux(path: Path) -> tuple[Credential, ...]:
    try:
        with zipfile.ZipFile(path) as zf:
            data = json.loads(zf.read("export.data"))
    except FileNotFoundError as err:
        raise VaultSieveError(f"Input file does not exist: {path}") from err
    except PermissionError as err:
        raise VaultSieveError(f"Cannot read input file: {path}") from err
    except zipfile.BadZipFile as err:
        raise VaultSieveError(f"Invalid 1Password 1PUX file: {err}") from err
    except (KeyError, json.JSONDecodeError) as err:
        raise VaultSieveError(f"Invalid 1PUX archive — missing or corrupt export.data: {err}") from err

    accounts = data.get("accounts")
    if not isinstance(accounts, list):
        raise VaultSieveError("1PUX file must contain an 'accounts' list.")

    credentials: list[Credential] = []
    index = 0
    for account in accounts:
        for vault in (account.get("vaults") or []):
            for item in (vault.get("items") or []):
                category = item.get("categoryUuid", "")
                if category != "001":
                    continue
                credential = _parse_login_item(item, index)
                if credential is not None:
                    credentials.append(credential)
                    index += 1
    return tuple(credentials)


def _parse_login_item(item: dict[str, Any], index: int) -> Credential | None:
    overview = item.get("overview") or {}
    details = item.get("details") or {}
    login_fields = details.get("loginFields") or []

    title = overview.get("title", "")
    url = overview.get("url", "")
    username = ""
    password = ""

    for field in login_fields:
        designation = field.get("designation", "")
        value = field.get("value", "")
        if designation == "username" and not username:
            username = str(value)
        elif designation == "password" and not password:
            password = str(value)

    urls: tuple[str, ...] = ()
    if url:
        urls = (url,)
    elif overview.get("urls"):
        url_list = [u.get("url", "") for u in overview["urls"] if u.get("url")]
        urls = tuple(url_list)

    return Credential(
        id=f"1password:{index}",
        source="1password",
        source_index=index,
        name=title,
        username=username,
        password=password,
        urls=urls,
        raw=item,
    )

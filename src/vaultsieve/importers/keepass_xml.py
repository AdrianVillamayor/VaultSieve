from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from vaultsieve.errors import VaultSieveError
from vaultsieve.models import Credential


def import_keepass_xml(path: Path) -> tuple[Credential, ...]:
    try:
        tree = ET.parse(path)  # noqa: S314
    except FileNotFoundError as err:
        raise VaultSieveError(f"Input file does not exist: {path}") from err
    except PermissionError as err:
        raise VaultSieveError(f"Cannot read input file: {path}") from err
    except ET.ParseError as err:
        raise VaultSieveError(f"Invalid KeePass XML: {err}") from err

    root = tree.getroot()
    root_group = root.find("Root/Group")
    if root_group is None:
        raise VaultSieveError("KeePass XML must contain a Root/Group element.")

    entries: list[dict[str, str]] = []
    _collect_entries(root_group, [], entries)

    credentials: list[Credential] = []
    for index, entry in enumerate(entries):
        url = entry.get("URL", "").strip()
        totp = entry.get("otp", "") or entry.get("TOTP Seed", "") or entry.get("TOTP", "")
        credentials.append(
            Credential(
                id=f"keepass:{index}",
                source="keepass",
                source_index=index,
                name=entry.get("Title", ""),
                username=entry.get("UserName", ""),
                password=entry.get("Password", ""),
                urls=(url,) if url else (),
                has_totp=bool(totp.strip()),
                raw=entry,
            )
        )
    return tuple(credentials)


def _collect_entries(
    group: ET.Element,
    path: list[str],
    result: list[dict[str, str]],
) -> None:
    group_name = _text(group, "Name")
    if group_name.lower() == "recycle bin":
        return
    current_path = [*path, group_name] if group_name else path

    for entry_el in group.findall("Entry"):
        fields: dict[str, str] = {"_group": "/".join(current_path)}
        for string_el in entry_el.findall("String"):
            key_el = string_el.find("Key")
            val_el = string_el.find("Value")
            if key_el is not None and key_el.text:
                fields[key_el.text] = (val_el.text or "") if val_el is not None else ""
        result.append(fields)

    for child_group in group.findall("Group"):
        _collect_entries(child_group, current_path, result)


def _text(element: ET.Element, tag: str) -> str:
    child = element.find(tag)
    return (child.text or "") if child is not None else ""

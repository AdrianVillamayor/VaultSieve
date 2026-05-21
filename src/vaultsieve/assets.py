from __future__ import annotations

import shutil
import sysconfig
from pathlib import Path

from vaultsieve.errors import VaultSieveError

LOGO_FILES = ("vaultsieve-icon.svg", "vaultsieve-wordmark.svg")


def logo_assets_dir() -> Path:
    checkout_assets = Path(__file__).resolve().parents[2] / "assets" / "logos"
    if checkout_assets.exists():
        return checkout_assets
    return Path(sysconfig.get_path("data")) / "assets" / "logos"


def copy_logo_assets(output_dir: Path) -> None:
    source_dir = logo_assets_dir()
    for filename in LOGO_FILES:
        source = source_dir / filename
        if not source.exists():
            raise VaultSieveError(f"Missing logo asset: {source}")
        try:
            shutil.copyfile(source, output_dir / filename)
        except OSError as err:
            raise VaultSieveError(f"Cannot copy logo asset: {filename}") from err

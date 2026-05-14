from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Literal

from vaultsieve.errors import VaultSieveError

OutputFormat = Literal["html", "json", "txt"]
ConfigKey = Literal[
    "check_breaches",
    "check_domains",
    "check_2fa",
    "check_known_breaches",
    "hibp_workers",
    "domain_workers",
    "min_password_length",
    "report_dir",
    "output_formats",
]

CONFIG_KEYS: tuple[ConfigKey, ...] = (
    "check_breaches",
    "check_domains",
    "check_2fa",
    "check_known_breaches",
    "hibp_workers",
    "domain_workers",
    "min_password_length",
    "report_dir",
    "output_formats",
)

OUTPUT_FORMATS: tuple[OutputFormat, ...] = ("html", "json", "txt")


@dataclass(frozen=True)
class AppConfig:
    check_breaches: bool = False
    check_domains: bool = True
    check_2fa: bool = False
    check_known_breaches: bool = False
    hibp_workers: int = 4
    domain_workers: int = 16
    min_password_length: int = 12
    report_dir: str = ""
    output_formats: tuple[OutputFormat, ...] = OUTPUT_FORMATS

    def to_dict(self) -> dict[str, bool | int | str | list[str]]:
        return {
            "check_breaches": self.check_breaches,
            "check_domains": self.check_domains,
            "check_2fa": self.check_2fa,
            "check_known_breaches": self.check_known_breaches,
            "hibp_workers": self.hibp_workers,
            "domain_workers": self.domain_workers,
            "min_password_length": self.min_password_length,
            "report_dir": self.report_dir,
            "output_formats": list(self.output_formats),
        }


def config_path() -> Path:
    override = os.environ.get("VAULTSIEVE_CONFIG_PATH")
    if override:
        return Path(override).expanduser()
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "vaultsieve" / "config.json"
    config_home = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return config_home / "vaultsieve" / "config.json"


def load_config(path: Path | None = None) -> AppConfig:
    resolved_path = path or config_path()
    if not resolved_path.exists():
        return AppConfig()
    try:
        raw = json.loads(resolved_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as err:
        raise VaultSieveError(f"Invalid config file: {resolved_path}") from err
    except OSError as err:
        raise VaultSieveError(f"Cannot read config file: {resolved_path}") from err
    if not isinstance(raw, dict):
        raise VaultSieveError(f"Invalid config file: {resolved_path}")
    return AppConfig(
        check_breaches=_as_bool(raw.get("check_breaches"), False),
        check_domains=_as_bool(raw.get("check_domains"), True),
        check_2fa=_as_bool(raw.get("check_2fa"), False),
        check_known_breaches=_as_bool(raw.get("check_known_breaches"), False),
        hibp_workers=_as_positive_int(raw.get("hibp_workers"), 4),
        domain_workers=_as_positive_int(raw.get("domain_workers"), 16),
        min_password_length=_as_positive_int(raw.get("min_password_length"), 12),
        report_dir=str(raw.get("report_dir") or ""),
        output_formats=_as_output_formats(raw.get("output_formats")),
    )


def save_config(config: AppConfig, path: Path | None = None) -> Path:
    resolved_path = path or config_path()
    try:
        resolved_path.parent.mkdir(parents=True, exist_ok=True)
        resolved_path.write_text(
            json.dumps(config.to_dict(), ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
    except OSError as err:
        raise VaultSieveError(f"Cannot write config file: {resolved_path}") from err
    return resolved_path


def set_config_value(key: str, value: str, path: Path | None = None) -> AppConfig:
    if key not in CONFIG_KEYS:
        raise VaultSieveError(f"Unsupported config key: {key}")
    config = load_config(path).to_dict()
    config[key] = parse_config_value(key, value)
    updated = AppConfig(**config)
    save_config(updated, path)
    return updated


def unset_config_value(key: str, path: Path | None = None) -> AppConfig:
    if key not in CONFIG_KEYS:
        raise VaultSieveError(f"Unsupported config key: {key}")
    config = load_config(path).to_dict()
    config[key] = AppConfig().to_dict()[key]
    updated = AppConfig(**config)
    save_config(updated, path)
    return updated


def parse_config_value(key: str, value: str) -> bool | int | str | list[str]:
    if key in {"check_breaches", "check_domains", "check_2fa", "check_known_breaches"}:
        normalized = value.strip().lower()
        if normalized in {"1", "true", "yes", "y", "on"}:
            return True
        if normalized in {"0", "false", "no", "n", "off"}:
            return False
        raise VaultSieveError(f"Config key {key} expects true or false.")
    if key in {"hibp_workers", "domain_workers", "min_password_length"}:
        try:
            parsed = int(value)
        except ValueError as err:
            raise VaultSieveError(f"Config key {key} expects an integer.") from err
        if parsed < 1:
            raise VaultSieveError(f"Config key {key} expects a positive integer.")
        return parsed
    if key == "report_dir":
        return value.strip()
    if key == "output_formats":
        return list(parse_output_formats(value))
    raise VaultSieveError(f"Unsupported config key: {key}")


def parse_output_formats(value: str) -> tuple[OutputFormat, ...]:
    requested = [part.strip().lower() for part in value.split(",") if part.strip()]
    if not requested or "all" in requested:
        return OUTPUT_FORMATS
    invalid = sorted(set(requested) - set(OUTPUT_FORMATS))
    if invalid:
        raise VaultSieveError(
            f"Unsupported output format: {', '.join(invalid)}. Use html, json, txt, or all."
        )
    result: list[OutputFormat] = []
    for item in requested:
        output_format = item  # type: ignore[assignment]
        if output_format not in result:
            result.append(output_format)
    return tuple(result)


def _as_bool(value: Any, default: bool) -> bool:
    return value if isinstance(value, bool) else default


def _as_positive_int(value: Any, default: int) -> int:
    return value if isinstance(value, int) and value > 0 else default


def _as_output_formats(value: Any) -> tuple[OutputFormat, ...]:
    if not isinstance(value, list):
        return OUTPUT_FORMATS
    valid = [item for item in value if item in OUTPUT_FORMATS]
    return tuple(valid) if valid else OUTPUT_FORMATS

# Adding a new password manager importer

VaultSieve ships with dedicated importers for the most popular password managers, plus a generic CSV importer for any manager that exports `name`, `url`, `username`, `password` columns.

## Supported formats

| Manager | Format | Status |
|---------|--------|--------|
| Bitwarden | JSON | Dedicated importer |
| LastPass | CSV | Dedicated importer |
| Dashlane | CSV, ZIP | Dedicated importers (ZIP extracts `credentials.csv`; `.dash` is encrypted and rejected with a clear error) |
| 1Password | CSV, 1PUX | Dedicated importers (auto-detected by extension) |
| KeePass/KeePassXC | CSV, XML | Dedicated importers (auto-detected by extension) |
| Keeper | CSV (headerless), JSON | Dedicated importers (CSV auto-detects headers vs positional) |
| RoboForm | CSV | Dedicated importer (BOM-safe via `utf-8-sig`) |
| Chrome | CSV | Generic CSV importer |
| NordPass | CSV | Generic CSV importer |
| Google Password Manager | CSV | Generic CSV importer |
| Firefox | CSV | Generic CSV (may need `name` column added) |

CSV-based importers use a shared `ColumnMap` system in `importers/_csv_base.py`. Adding a new CSV format is ~20 lines.

## Step-by-step: adding a dedicated importer

### 1. Create the importer module

Create `src/vaultsieve/importers/<manager>.py`. The function must:

- Accept a `Path` and return `tuple[Credential, ...]`
- Set `id` as `"<manager>:<index>"` and `source` matching the `InputFormat` literal
- Raise `VaultSieveError` for user-facing errors (bad file, missing fields)
- Detect passkeys, TOTP, and SSH keys when the format supports them
- Store the original item in `raw` (needed for clean output)

Minimal example:

```python
from __future__ import annotations

from pathlib import Path

from vaultsieve.errors import VaultSieveError
from vaultsieve.models import Credential


def import_example(path: Path) -> tuple[Credential, ...]:
    # Parse the file, build Credential tuples
    ...
    return tuple(credentials)


def load_example_data(path: Path) -> ...:
    # Return raw parsed data (needed by cleaner for clean output)
    ...
```

### 2. Register the format in models

Add the format name to `InputFormat` in `src/vaultsieve/models.py`:

```python
InputFormat = Literal["bitwarden", "csv", "example"]
```

### 3. Wire the importer into the audit pipeline

In `src/vaultsieve/audit.py`, add to `import_credentials()`:

```python
if input_format == "example":
    return import_example(input_path)
```

### 4. Wire the cleaner

In `src/vaultsieve/cleaner.py`, add a `_write_clean_example()` function and dispatch it from `write_clean_output()`. The cleaner must:

- Read the original file
- Remove entries whose `source_index` matches a removed credential
- Write the result in the same format as the original

### 5. Update CLI and TUI

- `src/vaultsieve/cli.py`: add `"example"` to the `--format` choices list
- `src/vaultsieve/tui.py`: add `"example"` to the format `Prompt.ask` choices and update auto-detection in `_run_guided_audit()` if the format has a recognizable file extension

### 6. Export the importer

Add to `src/vaultsieve/importers/__init__.py`:

```python
from vaultsieve.importers.example import import_example
```

### 7. Add tests

Create tests in `tests/` that:

- Import a minimal fixture file and verify the resulting `Credential` tuples
- Verify error handling for malformed input
- Verify clean output writes the correct format
- Run a full `run_audit()` cycle with the new format

### Checklist

- [ ] Importer module in `src/vaultsieve/importers/`
- [ ] `InputFormat` updated in `models.py`
- [ ] `import_credentials()` dispatch in `audit.py`
- [ ] Cleaner dispatch in `cleaner.py`
- [ ] CLI `--format` choices updated
- [ ] TUI format choices and auto-detection updated
- [ ] Importer exported from `importers/__init__.py`
- [ ] Tests added
- [ ] `README.md` features list updated

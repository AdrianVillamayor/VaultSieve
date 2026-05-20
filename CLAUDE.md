# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Install for development (or use uv)
python3 -m venv .venv && .venv/bin/python -m pip install -e '.[dev]'

# Run app
./vaultsieve                                          # interactive TUI
./vaultsieve audit <export> --format bitwarden|csv|lastpass|dashlane|1password|keepass|keeper|roboform
./vaultsieve config list                              # manage settings

# Tests and lint
uv run pytest                    # all tests
uv run pytest tests/test_analyzers.py -k test_name    # single test
uv run ruff check .             # lint
```

## Architecture

Three-phase pipeline: **import → analyze → report**, orchestrated by `audit.py::run_audit()`.

**Importers** (`src/vaultsieve/importers/`) convert vault exports into frozen `Credential` dataclasses. Supports Bitwarden JSON, generic CSV, LastPass, Dashlane (CSV/ZIP), 1Password (CSV/1PUX), KeePass (CSV/XML), Keeper (CSV headerless/JSON), and RoboForm (CSV with BOM). CSV-based importers share a `ColumnMap` system in `_csv_base.py`.

**Analyzers** (`src/vaultsieve/analyzers/`) each produce `Finding` tuples from credentials. Run in sequence: duplicates → password quality → insecure_http → domain_concentration → optional checks (HIBP breaches, domain existence, known breaches, 2FA). Optional checks use `ThreadPoolExecutor` for concurrency.

**Reports** (`src/vaultsieve/reports/`) render to terminal (Rich), TXT, JSON, and self-contained HTML with embedded CSS/JS. The HTML report has a dashboard (score orb, severity chart, category guide), action board, filters, and findings table.

**Cleaner** (`src/vaultsieve/cleaner.py`) writes deduplicated/cleaned exports without modifying originals.

**TUI** (`src/vaultsieve/tui.py`) uses `questionary` for arrow-key interactive prompts and Rich for styled output (panels, progress).

**Models** (`src/vaultsieve/models.py`): `Credential`, `Finding`, `AuditReport`, `AuditOptions` — all frozen dataclasses. Severity levels: critical > high > medium > low > obsolete.

## Key Rules

- HIBP checks must remain opt-in and use k-anonymity (SHA-1 prefix only). Never send full passwords externally.
- Reports must never include plaintext passwords. Use `Credential.safe_reference()`.
- Expected user-facing errors raise `VaultSieveError` (clean exit, no traceback).
- Do not run git operations unless explicitly asked.
- Documentation goes under `docs/specs/` or `docs/plans/` — not `docs/superpowers/`.
- Ruff config: line-length 100, target py311, select E/F/I/UP, ignore E501.

## Config

Persistent `AppConfig` at `~/.config/vaultsieve/config.json`. Key defaults: all network checks off, `min_password_length=12`, `hibp_workers=4`, `domain_workers=16`.

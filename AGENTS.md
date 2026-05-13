# AGENTS.md

## Current State

- This repo is now a packaged Python preview app named `vaultsieve`.
- Source lives under `src/vaultsieve/`; root `main.py` is only a compatibility shim to `vaultsieve.cli`.
- Current preview version is `0.1.0a1` in both `pyproject.toml` and `src/vaultsieve/__init__.py`.
- There is no CI, formatter config, or pre-commit config yet.

## Commands

- Install locally for development: `python3 -m venv .venv && .venv/bin/python -m pip install -e '.[dev]'`.
- Run the interactive assistant through the local launcher: `./vaultsieve`.
- Run an explicit TUI alias: `./vaultsieve tui`.
- Run a direct audit: `./vaultsieve audit <export> --format bitwarden|csv`.
- The launcher delegates to `.venv/bin/vaultsieve` and prints setup instructions if `.venv` is missing.
- Run tests: `.venv/bin/python -m pytest`.

## Git Workflow

- Do not run git operations unless the user explicitly asks for the exact git action. This includes status, diff, add, commit, branch, checkout, pull, push, reset, and stash.

## Architecture Notes

- `src/vaultsieve/importers/` converts Bitwarden JSON or generic CSV into shared `Credential` models.
- `src/vaultsieve/analyzers/` produces findings from normalized credentials only.
- `src/vaultsieve/reports/` renders terminal, TXT, JSON, and HTML reports; do not include full plaintext passwords in reports.
- `src/vaultsieve/cleaner.py` writes optional clean outputs without modifying original exports.
- HIBP checks are opt-in, use SHA-1 k-anonymity, cache unique passwords in memory, and use limited thread concurrency.
- Expected user-facing failures should raise `VaultSieveError` so CLI/TUI can exit without large tracebacks.

## Project Direction

- The active design spec is `docs/specs/2026-05-13-vaultsieve-design.md`.
- Documentation files belong directly under `docs/` in the appropriate concrete subfolder, such as `docs/specs/` or `docs/plans/`; do not create or use a `docs/superpowers/` directory.
- First supported inputs are Bitwarden JSON and generic CSV with `name`, `url`, `username`, `password` columns.
- UX includes `vaultsieve` interactive assistant, `vaultsieve tui`, and `vaultsieve audit`; do not assume Textual unless the spec changes.
- Have I Been Pwned checking must remain opt-in and use k-anonymity; never send full passwords externally.

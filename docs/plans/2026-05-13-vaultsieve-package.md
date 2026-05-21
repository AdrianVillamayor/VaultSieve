# VaultSieve Package Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking. Do not run Git commands unless the user explicitly asks for a specific Git action.

**Goal:** Turn the current Bitwarden duplicate script into a packaged Python project named `vaultsieve` with CLI, simple Rich-based TUI, importers, analyzers, reports, cleanup, and tests.

**Architecture:** Source-specific importers normalize vault entries into shared models. Analyzers operate only on normalized credentials and produce findings. CLI and TUI orchestrate imports, checks, reports, and optional cleanup without modifying the original input file.

**Tech Stack:** Python 3.11+, `pytest`, `rich`, standard-library CSV/JSON/HTML, optional stdlib `urllib` for Have I Been Pwned k-anonymity lookup.

---

## File Structure

- Create `pyproject.toml`: package metadata, dependencies, console scripts, pytest config.
- Create `src/vaultsieve/models.py`: `Credential`, `Finding`, `AuditReport`, options, severities.
- Create `src/vaultsieve/importers/bitwarden.py`: Bitwarden JSON importer and cleaner support.
- Create `src/vaultsieve/importers/csv_generic.py`: generic CSV importer and cleaner support.
- Create `src/vaultsieve/analyzers/duplicates.py`: exact duplicate and reused-password findings.
- Create `src/vaultsieve/analyzers/passwords.py`: empty, short, complexity, and similarity checks.
- Create `src/vaultsieve/analyzers/breaches.py`: opt-in Have I Been Pwned check with injectable lookup for tests.
- Create `src/vaultsieve/audit.py`: orchestration entrypoint for import and analysis.
- Create `src/vaultsieve/cleaner.py`: write cleaned Bitwarden JSON or CSV without exact duplicates.
- Create `src/vaultsieve/reports/`: terminal, text, JSON, and HTML renderers.
- Create `src/vaultsieve/cli.py`: `vaultsieve audit` and `vaultsieve tui` commands.
- Create `src/vaultsieve/tui.py`: simple Rich prompt workflow.
- Create `tests/`: focused tests for importers, analyzers, reports, cleanup, and CLI smoke behavior.
- Keep root `main.py` as a compatibility shim that delegates to `vaultsieve.cli`.

## Tasks

### Task 1: Package Skeleton

- [ ] Add `pyproject.toml` with package metadata, `rich`, `pytest`, and `vaultsieve` console script.
- [ ] Create `src/vaultsieve/__init__.py` exposing `__version__`.
- [ ] Replace root `main.py` with a small shim that calls `vaultsieve.cli.main`.
- [ ] Verify import with `python3 -m pytest --version` after installing dev dependencies.

### Task 2: Core Models

- [ ] Create dataclasses in `src/vaultsieve/models.py` for credentials, findings, audit reports, and audit options.
- [ ] Keep plaintext passwords only in memory and exclude them from report serialization helpers.
- [ ] Add tests for report-safe credential references.

### Task 3: Importers

- [ ] Implement Bitwarden JSON import for login items where `type == 1`.
- [ ] Implement CSV import with required columns `name`, `url`, `username`, `password`.
- [ ] Preserve source index and source type on each credential.
- [ ] Add tests for valid imports and invalid input shape.

### Task 4: Offline Analyzers

- [ ] Implement exact duplicate detection using normalized name, username, password, and sorted URLs.
- [ ] Implement reused-password detection across different credentials.
- [ ] Implement password quality checks for empty, short, low-complexity, and similarity to name or username.
- [ ] Add tests for each finding category and severity.

### Task 5: Optional Breach Analyzer

- [ ] Implement SHA-1 prefix/suffix k-anonymity lookup with no full-password transmission.
- [ ] Make breach checking opt-in through `AuditOptions.check_breaches`.
- [ ] Inject the lookup function for tests so no real network call is required.
- [ ] Add tests for breached and not-breached results.

### Task 6: Audit Orchestration

- [ ] Implement `run_audit(input_path, input_format, options)` in `src/vaultsieve/audit.py`.
- [ ] Return an `AuditReport` containing credentials, findings, input metadata, and summary counts.
- [ ] Add tests proving CLI/TUI can use one shared orchestration path.

### Task 7: Reports

- [ ] Implement terminal summary with Rich tables.
- [ ] Implement TXT report with readable findings.
- [ ] Implement JSON report with stable machine-readable shape and no plaintext passwords.
- [ ] Implement HTML report with escaped content and no plaintext passwords.
- [ ] Add tests for JSON report shape and plaintext password exclusion.

### Task 8: Cleanup

- [ ] Implement clean output generation for Bitwarden JSON and CSV.
- [ ] Remove only later entries in exact duplicate groups.
- [ ] Never modify the original input file.
- [ ] Add tests for Bitwarden and CSV cleanup output.

### Task 9: CLI

- [ ] Implement `vaultsieve audit <input> --format bitwarden|csv`.
- [ ] Add `--check-breaches`, `--report-dir`, `--clean-output`, and `--min-severity` options.
- [ ] Generate terminal, TXT, JSON, and HTML reports by default.
- [ ] Add CLI smoke tests with temporary files.

### Task 10: TUI

- [ ] Implement `vaultsieve tui` with Rich prompts for input path, format, breach check, report directory, and optional cleanup.
- [ ] Show summary and findings tables after audit.
- [ ] Ask for explicit confirmation before clean output generation.
- [ ] Keep the TUI simple; do not introduce Textual.

### Task 11: Documentation And Verification

- [ ] Update `README.md` with install, CLI, TUI, input formats, reports, and safety notes.
- [ ] Run `python3 -m pytest`.
- [ ] Run a CLI smoke audit against a small temporary Bitwarden fixture.
- [ ] Do not commit unless the user explicitly asks for a Git commit.

## Self-Review

- Spec coverage: Bitwarden, CSV, CLI, TUI, reports, cleanup, HIBP opt-in, and no-plaintext-password report safety are covered.
- Placeholder scan: no TBD/TODO placeholders are required for implementation.
- Type consistency: plan consistently uses `Credential`, `Finding`, `AuditReport`, `AuditOptions`, and `run_audit`.
- Repository constraint: Git operations are explicitly excluded unless requested by the user.

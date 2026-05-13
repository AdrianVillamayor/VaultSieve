# VaultSieve Design

## Goal

VaultSieve is a Python password-vault auditor. It helps users inspect exported password data for duplicates, weak passwords, reused passwords, likely mistakes, and optionally known breached passwords.

The first version supports Bitwarden JSON exports and a generic CSV format. The project is designed so additional importers can be added later without changing the analysis engine.

## Product Shape

VaultSieve will be a formal Python package with two user-facing entry points:

- `vaultsieve audit`: non-interactive CLI for automation and repeatable audits.
- `vaultsieve tui`: guided terminal interface for users who want to complete the whole flow interactively.

The TUI is the primary experience for the first version. It should guide the user through selecting input, configuring checks, running the audit, reviewing findings, exporting reports, and optionally generating a cleaned file without exact duplicates.

## Supported Inputs

### Bitwarden JSON

VaultSieve will read standard Bitwarden JSON exports and import login items. The importer will preserve source indexes so findings and optional cleanup can refer back to original items safely.

### Generic CSV

VaultSieve will support a simple CSV format with expected columns:

- `name`
- `url`
- `username`
- `password`

The CSV importer can be extended later to support column mapping, but the first version should keep the expected format explicit.

## Normalized Data Model

Importers convert source-specific data into a shared credential model:

- `id`: internal stable identifier for this audit run.
- `source`: source type such as `bitwarden` or `csv`.
- `source_index`: original item or row index.
- `name`: entry name.
- `username`: login username.
- `password`: login password, kept in memory for analysis.
- `urls`: list of associated URLs.
- `raw`: optional source-specific metadata needed for cleanup.

Analysis and reporting should depend on this normalized model, not directly on Bitwarden or CSV structures.

## Checks

VaultSieve will implement these checks in the first version:

- Exact duplicate credentials: same normalized name, username, password, and URLs.
- Reused passwords: same password used by more than one credential.
- Empty passwords.
- Short passwords.
- Low-complexity passwords.
- Passwords similar to the entry name or username.
- Optional known-breach check using Have I Been Pwned k-anonymity.

Each finding will include:

- severity: `critical`, `high`, `medium`, or `low`.
- category: duplicate, reuse, weak, empty, similar, breached, or input issue.
- affected credential IDs.
- human-readable explanation.
- suggested next action.

## Breach Checking

Have I Been Pwned checks are disabled by default. The user must explicitly enable them with a CLI flag or through the TUI.

When enabled, VaultSieve will use the k-anonymity password API pattern:

- hash the password locally with SHA-1;
- send only the first five hash characters;
- compare the returned suffixes locally.

VaultSieve must not send full passwords to external services.

## Reports

VaultSieve will provide three report outputs plus terminal display:

- Terminal summary for quick review.
- TXT report for human-readable archive.
- JSON report for automation.
- HTML report for local visual review.

Reports should not include full passwords. They may include credential names, usernames, URLs, source indexes, finding categories, severities, explanations, and recommended actions. If a stable reference is needed, use internal IDs or safe fingerprints rather than plaintext passwords.

## Optional Cleanup

VaultSieve will never modify the original input file.

Cleanup is optional and must require explicit user action:

- CLI: a flag such as `--clean-output <path>`.
- TUI: a confirmation step before writing the cleaned file.

The first cleanup feature only removes exact duplicates. It keeps the first occurrence and removes later entries from the generated clean output. Password reuse and weak passwords are reported but not automatically modified.

Cleanup output is source-aware:

- Bitwarden JSON cleanup writes a Bitwarden-like JSON file with duplicate login items removed.
- CSV cleanup writes a CSV file with duplicate rows removed.

## TUI Design

The first TUI should be simple and dependable, using `rich` prompts and tables rather than a full reactive Textual app.

The guided flow:

1. Select input file.
2. Select input format: Bitwarden JSON or generic CSV.
3. Configure checks, including whether to enable Have I Been Pwned.
4. Run audit.
5. View summary by severity.
6. Browse findings by category or severity.
7. Export TXT, JSON, and HTML reports.
8. Optionally generate a clean file without exact duplicates after confirmation.

This keeps dependencies modest while still helping the user perform the whole workflow without memorizing CLI flags.

## CLI Design

The non-interactive command should support repeatable audits:

```bash
vaultsieve audit path/to/export.json --format bitwarden
vaultsieve audit path/to/passwords.csv --format csv --check-breaches
vaultsieve audit export.json --format bitwarden --report-dir reports --clean-output clean.json
```

Expected options:

- input path.
- input format.
- report directory.
- enable breach checking.
- optional clean output path.
- optional severity threshold for terminal output.

## Package Structure

The project will use a standard package layout:

```text
pyproject.toml
src/vaultsieve/
  __init__.py
  cli.py
  tui.py
  models.py
  cleaner.py
  importers/
    __init__.py
    bitwarden.py
    csv_generic.py
  analyzers/
    __init__.py
    duplicates.py
    passwords.py
    breaches.py
  reports/
    __init__.py
    terminal.py
    text.py
    json.py
    html.py
tests/
```

The implementation should keep modules small and focused. Importers parse data, analyzers produce findings, reports render findings, and cleanup writes new files.

## Testing

Initial tests should cover:

- Bitwarden import of login items.
- Generic CSV import.
- Exact duplicate detection.
- Password reuse detection.
- Empty, short, low-complexity, and similar-password checks.
- JSON report structure.
- Cleanup output that removes only exact duplicates.

Breach checking should be written so the HTTP lookup can be mocked in tests.

## Non-Goals For First Version

- No browser UI.
- No direct connection to password-manager accounts.
- No automatic password changing.
- No full Textual application unless the simple Rich TUI proves insufficient.
- No support for additional vault formats beyond Bitwarden JSON and generic CSV.

## Safety Principles

- Treat all inputs and outputs as sensitive.
- Do not log full passwords.
- Do not include full passwords in reports.
- Do not modify original exports.
- Keep breach checking opt-in.
- Prefer explicit user confirmation before writing cleaned outputs.

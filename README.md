# VaultSieve

Logo assets belong in [`assets/logos/`](assets/logos/).

VaultSieve audits exported password vaults for exact duplicates, reused passwords, weak passwords, likely mistakes, and optionally known breached passwords.

Current version: `0.1.0a1` preview. Treat exported vault files and generated reports as sensitive.

The project currently supports:

- Bitwarden JSON exports.
- Generic CSV files with `name`, `url`, `username`, `password` columns.

## Install For Development

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
```

After installing, the local launcher can be used from the repo root:

```bash
./vaultsieve
```

## CLI

For the lowest-friction flow, run VaultSieve without arguments:

```bash
./vaultsieve
```

This opens an interactive assistant where you can choose what to do, select the input file, run the audit, export reports, and optionally create a clean file.

Direct commands still exist for automation.

Check the installed version:

```bash
./vaultsieve --version
```

Run an audit and write TXT, JSON, and HTML reports:

```bash
./vaultsieve audit path/to/export.json --format bitwarden
./vaultsieve audit path/to/passwords.csv --format csv
```

Enable Have I Been Pwned checking explicitly:

```bash
./vaultsieve audit path/to/export.json --format bitwarden --check-breaches
```

HIBP checks are cached per unique password and run with limited concurrency. The default is four workers; advanced users can tune it:

```bash
./vaultsieve audit path/to/export.json --format bitwarden --check-breaches --hibp-workers 8
```

Write reports to a chosen directory and generate a clean output without exact duplicates:

```bash
./vaultsieve audit path/to/export.json --format bitwarden --report-dir reports --clean-output clean.json
```

## TUI

Start the guided terminal flow explicitly:

```bash
./vaultsieve tui
```

The TUI helps select the input file, choose the format, configure breach checking, run the audit, write reports, and optionally create a clean output after confirmation. Audits show terminal progress while importing, analyzing, checking breaches, writing reports, and creating clean output.

## Safety

- VaultSieve never modifies the original input file.
- Reports do not include full plaintext passwords.
- Have I Been Pwned checks are off by default.
- Breach checks use k-anonymity and send only the first five SHA-1 hash characters, never the full password.
- Breach checks query each unique password once, cache results in memory for that run, and use limited concurrency.

## Exit Codes

- `0`: command completed successfully.
- `1`: expected user-facing error, such as missing input file or invalid export format.
- `130`: cancelled with `Ctrl+C`.

## Tests

```bash
python3 -m pytest
```

# VaultSieve

Logo assets belong in [`assets/logos/`](assets/logos/).

VaultSieve audits exported password vaults for duplicates, reused passwords, weak passwords, likely mistakes, stale services, missing 2FA context, and optional breach signals.

Current version: `1.0.0`. Treat exported vault files and generated reports as sensitive; reports exclude plaintext passwords but can include usernames, emails, URLs, and account names.

## Features

- Bitwarden JSON exports.
- Generic CSV files with `name`, `url`, `username`, `password` columns.
- Interactive assistant by default with `vaultsieve`.
- Direct automation with `vaultsieve audit`.
- Terminal, TXT, JSON, and HTML reports.
- HTML category dashboard with affected-entry filtering.
- Optional clean output for safe exact duplicates and obsolete entries.
- Optional Have I Been Pwned password checks using k-anonymity, response padding, unique-password caching, and limited concurrency.
- Optional known breached service checks using the public HIBP breach catalogue without sending emails or usernames.
- Optional 2FA availability checks using cached `2fa.directory` TOTP data.
- Optional domain existence checks to flag credentials for services that may no longer exist.
- Persistent settings through `vaultsieve config` and the TUI Settings screen.
- Passkey and SSH-key awareness to avoid password-specific false positives.

## Quick Start

**Install with pipx from GitHub:**

```bash
pipx install git+https://github.com/AdrianVillamayor/VaultSieve.git
vaultsieve
```

**Or via install script:**

```bash
curl -fsSL https://raw.githubusercontent.com/AdrianVillamayor/VaultSieve/main/install.sh | bash
```

From a local checkout, run:

```bash
./install.sh
```

**Future Homebrew flow:**

```bash
brew tap AdrianVillamayor/vaultsieve
brew install vaultsieve
vaultsieve
```

See [`docs/install.md`](docs/install.md) for install details, [`docs/privacy.md`](docs/privacy.md) for privacy notes, and [`docs/release.md`](docs/release.md) for release preparation.

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

Run an audit and write the configured report formats:

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

Check services with public breach history without sending emails or usernames:

```bash
./vaultsieve audit path/to/export.json --format bitwarden --check-known-breaches
```

This downloads and caches the public HIBP breach catalogue, then matches saved web domains locally. It does not prove that your specific account or email was exposed.

Check services that support TOTP-based 2FA but do not have TOTP stored in the vault:

```bash
./vaultsieve audit path/to/export.json --format bitwarden --check-2fa
```

This uses cached `2fa.directory` v4 TOTP data. A finding means the service supports TOTP and the exported entry does not include a stored TOTP secret. It does not prove 2FA is disabled, because you may use another authenticator, passkey, or hardware key.

Check whether saved credential domains still exist:

```bash
./vaultsieve audit path/to/export.json --format bitwarden --check-domains
```

Domain checks use DNS resolution, try the `www.` variant before marking a domain missing, skip app URLs such as `androidapp://...`, skip SSH keys, and mark entries as probably obsolete when the domain no longer exists.

Write reports to a chosen directory and generate a clean output without exact duplicates:

```bash
./vaultsieve audit path/to/export.json --format bitwarden --report-dir reports --clean-output clean.json
```

Choose what the clean output removes:

```bash
./vaultsieve audit path/to/export.json --format bitwarden --check-domains --clean-output clean.json --clean-mode obsolete
./vaultsieve audit path/to/export.json --format bitwarden --check-domains --clean-output clean.json --clean-mode all
```

Clean modes are `duplicates`, `obsolete`, and `all`. Duplicate cleanup removes exact duplicates only when VaultSieve can choose a clear keeper from metadata such as update time and richness. Ambiguous duplicate groups are kept. Obsolete entries are credentials whose saved web domain no longer resolves.

## Persistent Config

VaultSieve stores defaults in a user config file. On first TUI launch, it asks for defaults such as breach checks, domain checks, 2FA checks, output formats, and report directory.

Show current settings:

```bash
./vaultsieve config list
```

Update one setting:

```bash
./vaultsieve config set check_domains true
./vaultsieve config set check_2fa false
./vaultsieve config set check_known_breaches true
./vaultsieve config set output_formats html,json,txt
```

Reset one setting:

```bash
./vaultsieve config unset report_dir
```

Explicit CLI flags always override persisted defaults for that run.

If `--report-dir` is omitted, reports are written next to the input file in `vaultsieve_reports/`.

## TUI

Start the guided terminal flow explicitly:

```bash
./vaultsieve tui
```

The TUI helps select the input file, choose the format, configure optional checks, run the audit, write reports, edit persistent settings, and optionally create a clean output after confirmation. Audits show terminal progress while importing, analyzing, checking external sources, writing reports, and creating clean output.

## Safety

- VaultSieve never modifies the original input file.
- Reports do not include full plaintext passwords.
- Reports can still include usernames, email addresses, URLs, account names, and source indexes.
- Treat generated TXT, JSON, HTML, and copied logo/report directories as sensitive local artifacts.
- Have I Been Pwned checks are off by default.
- Domain, 2FA availability, and known breached service checks are off by default unless enabled in config or with CLI flags.
- HIBP password checks use k-anonymity and send only the first five SHA-1 hash characters, never the full password.
- HIBP password checks request padded responses, query each unique password once, cache results in memory for that run, and use limited concurrency.
- Known breached service checks do not send emails or usernames; they download a public breach catalogue and match domains locally.
- 2FA checks download cached public TOTP-support data from `2fa.directory`; they do not check your account state.
- Generated HTML reports include attribution when they show data derived from HIBP or `2fa.directory`.

## Exit Codes

- `0`: command completed successfully.
- `1`: expected user-facing error, such as missing input file or invalid export format.
- `130`: cancelled with `Ctrl+C`.

## Tests

```bash
python3 -m pytest
```

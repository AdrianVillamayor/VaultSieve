# Changelog

## 0.1.0a1 - Preview

- Package preview for `vaultsieve`.
- Adds interactive assistant via `vaultsieve` and `vaultsieve tui`.
- Keeps direct automation command via `vaultsieve audit`.
- Supports Bitwarden JSON and generic CSV imports.
- Detects exact duplicates, reused passwords, empty passwords, short passwords, low-complexity passwords, and passwords similar to entry name or username.
- Adds optional Have I Been Pwned checking using k-anonymity, unique-password caching, and limited concurrency.
- Generates terminal, TXT, JSON, and HTML reports without full plaintext passwords.
- Can optionally generate clean Bitwarden JSON or CSV outputs without exact duplicates.
- Adds clean exits for expected errors and `Ctrl+C` cancellation.

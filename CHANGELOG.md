# Changelog

## 1.0.0 — 2025-05-20

- First stable release.
- Added dedicated importers for LastPass (CSV), Dashlane (CSV/ZIP), 1Password (CSV/1PUX), KeePass/KeePassXC (CSV/XML), Keeper (CSV headerless/JSON), and RoboForm (CSV with BOM).
- Redesigned HTML report with health score orb, severity chart, action board, and filterable findings table.
- Added dark/light theme toggle with system preference detection and localStorage persistence.
- Responsive HTML report layout for mobile and tablet screens.
- Added domain concentration analysis for domains with many saved accounts.
- Added insecure HTTP URL detection with automatic HTTPS redirect filtering.
- Added known breached services check using the public HIBP breach catalogue.
- Added 2FA availability checks using cached 2fa.directory TOTP data.
- Added SSH key and passkey awareness across all analyzers.
- Added CI workflow with lint and multi-version test matrix.
- Added persistent config with CLI and TUI settings management.
- Added auto-detection of input format from file extension in TUI.
- Migrated TUI prompts to arrow-key selection with questionary.
- Improved duplicate cleanup scoring with metadata-based keeper selection.

## 0.1.0a1

- Initial packaged Python preview app.
- Added Bitwarden JSON and generic CSV importers.
- Added terminal, TXT, JSON, and offline HTML reports.
- Added duplicate, reuse, weak password, insecure HTTP, optional HIBP password, domain, 2FA Directory, and known breached service checks.
- Added safe clean-output generation for exact duplicates and obsolete domain entries.
- Added persistent config through CLI and TUI settings.
- Added passkey and SSH-key awareness to avoid web/password false positives.

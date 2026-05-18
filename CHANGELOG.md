# Changelog

## 1.0.0

- First stable release.
- Redesigned HTML report with health score, severity chart, category guide, action board, and filterable findings table.
- Added domain concentration analysis for domains with many saved accounts.
- Added insecure HTTP URL detection with automatic HTTPS redirect filtering.
- Added known breached services check using the public HIBP breach catalogue.
- Added 2FA availability checks using cached 2fa.directory TOTP data.
- Added SSH key and passkey awareness across all analyzers.
- Added CI workflow with lint and multi-version test matrix.
- Added persistent config with CLI and TUI settings management.
- Improved duplicate cleanup scoring with metadata-based keeper selection.

## 0.1.0a1

- Initial packaged Python preview app.
- Added Bitwarden JSON and generic CSV importers.
- Added terminal, TXT, JSON, and offline HTML reports.
- Added duplicate, reuse, weak password, insecure HTTP, optional HIBP password, domain, 2FA Directory, and known breached service checks.
- Added safe clean-output generation for exact duplicates and obsolete domain entries.
- Added persistent config through CLI and TUI settings.
- Added passkey and SSH-key awareness to avoid web/password false positives.

# VaultSieve Privacy Notes

Vault exports and generated reports are sensitive. VaultSieve does not modify the original export file and report renderers avoid full plaintext passwords.

## Local Checks

- Duplicate, reuse, weak password, similar password, insecure `http://`, and clean-output decisions run locally.
- Domain extraction skips non-web schemes such as `androidapp://` and skips SSH-key entries where web checks do not apply.
- Clean output is written to a new file only when requested.

## Have I Been Pwned Password Checks

- Disabled unless `check_breaches` or `--check-breaches` is enabled.
- VaultSieve hashes each unique password locally with SHA-1.
- Only the first five SHA-1 characters are sent to `api.pwnedpasswords.com`.
- The full password and full hash are never sent.
- Requests include `Add-Padding: true`; padded rows with count `0` are ignored.
- Results are cached in memory for the current audit run.

## Known Breached Services

- Disabled unless `check_known_breaches` or `--check-known-breaches` is enabled.
- VaultSieve downloads the public HIBP breach catalogue and caches it locally.
- Matching happens locally against saved web domains.
- Emails, usernames, and passwords are not sent.
- Findings mean a service has public breach history, not that your account or email was exposed.

## 2FA Directory Checks

- Disabled unless `check_2fa` or `--check-2fa` is enabled.
- VaultSieve downloads cached TOTP-support data from `2fa.directory`.
- Matching happens locally against saved web domains.
- Findings mean a service supports TOTP and the vault entry does not store a TOTP secret.
- This does not prove 2FA is disabled; you may use a separate authenticator, passkey, SMS, or hardware key.

## Domain Checks

- Disabled unless `check_domains` or `--check-domains` is enabled.
- VaultSieve performs DNS resolution for unique web domains and tries the `www.` variant before marking a domain missing.
- DNS queries reveal looked-up domains to the configured resolver.

## LeakCheck

VaultSieve does not use LeakCheck. Public LeakCheck queries can involve emails, usernames, or truncated email hashes, which can reveal personal identifiers or enable correlation. If identity-leak checks are added later, they should be explicit opt-in and documented separately.

## Reports

- Reports exclude full plaintext passwords.
- Reports can include names, usernames, URLs, source indexes, categories, recommendations, and attribution.
- Treat TXT, JSON, and HTML reports as sensitive.

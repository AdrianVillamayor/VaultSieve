# Installing VaultSieve

VaultSieve is a Python CLI/TUI app. The intended user command is:

```bash
vaultsieve
```

## Recommended: pipx

Install from the GitHub repository:

```bash
pipx install git+https://github.com/AdrianVillamayor/VaultSieve.git
vaultsieve
```

Upgrade:

```bash
pipx upgrade vaultsieve
```

Uninstall:

```bash
pipx uninstall vaultsieve
```

## Install Script

From a local checkout, the script installs the current directory with `pipx`:

```bash
./install.sh
```

When the repository is public, users can install with:

```bash
curl -fsSL https://raw.githubusercontent.com/AdrianVillamayor/VaultSieve/main/install.sh | bash
```

To test a fork or alternate repository:

```bash
VAULTSIEVE_REPO=https://github.com/your-user/VaultSieve.git \
  curl -fsSL https://raw.githubusercontent.com/AdrianVillamayor/VaultSieve/main/install.sh | bash
```

## Homebrew Plan

Homebrew support should use a tap once releases are available:

```bash
brew tap AdrianVillamayor/vaultsieve
brew install vaultsieve
vaultsieve
```

This requires a release archive and a Homebrew formula in the tap repository.

## Development Install

From a local checkout:

```bash
python3 -m venv .venv
.venv/bin/python -m pip install -e '.[dev]'
./vaultsieve
```

The local `./vaultsieve` launcher delegates to `.venv/bin/vaultsieve` and prints setup instructions if the virtual environment is missing.

## Build Check

Before publishing to package indexes:

```bash
.venv/bin/python -m pip install -e '.[dev]'
.venv/bin/python -m build
.venv/bin/python -m twine check dist/*
```

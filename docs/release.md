# VaultSieve Release Checklist

This repo is currently at preview version `0.1.0a1`.

## Preflight

- Confirm `pyproject.toml` and `src/vaultsieve/__init__.py` have the same version.
- Update `CHANGELOG.md`.
- Run tests: `.venv/bin/python -m pytest`.
- Build package: `.venv/bin/python -m build`.
- Check package metadata: `.venv/bin/python -m twine check dist/*`.

## PyPI And pipx

Once published to PyPI, users can install with:

```bash
pipx install vaultsieve
vaultsieve
```

Until then, use the GitHub install path:

```bash
pipx install git+https://github.com/AdrianVillamayor/VaultSieve.git
```

## Homebrew Tap

Create a tap repository such as `AdrianVillamayor/homebrew-vaultsieve` or `AdrianVillamayor/homebrew-tap`.

Expected user flow:

```bash
brew tap AdrianVillamayor/vaultsieve
brew install vaultsieve
vaultsieve
```

The formula should install the released Python package and expose the `vaultsieve` console script.

## Install Script

`install.sh` uses `pipx` and installs from:

```text
https://github.com/AdrianVillamayor/VaultSieve.git
```

If the final GitHub owner or repository changes, update:

- `install.sh`
- `docs/install.md`
- `pyproject.toml` project URLs
- README install commands

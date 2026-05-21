#!/usr/bin/env sh
set -eu

APP_NAME="vaultsieve"
DEFAULT_REPO="https://github.com/AdrianVillamayor/VaultSieve.git"
SCRIPT_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ -n "${VAULTSIEVE_REPO:-}" ]; then
  INSTALL_SPEC="git+$VAULTSIEVE_REPO"
elif [ -f "$SCRIPT_DIR/pyproject.toml" ] && [ -d "$SCRIPT_DIR/src/vaultsieve" ]; then
  INSTALL_SPEC="$SCRIPT_DIR"
else
  INSTALL_SPEC="git+$DEFAULT_REPO"
fi

info() {
  printf '%s\n' "$1"
}

fail() {
  printf 'Error: %s\n' "$1" >&2
  exit 1
}

command_exists() {
  command -v "$1" >/dev/null 2>&1
}

info "Installing VaultSieve..."

command_exists python3 || fail "python3 is required. Install Python 3.11+ first."

if ! command_exists pipx; then
  info "pipx is required for the easiest install path."
  info "Install pipx, then rerun this script:"
  info "  brew install pipx"
  info "  pipx ensurepath"
  info "Alternatively install manually: python3 -m pip install --user pipx"
  exit 1
fi

if pipx list 2>/dev/null | grep -q "package $APP_NAME"; then
  info "VaultSieve is already installed with pipx. Reinstalling from $INSTALL_SPEC"
  pipx install --force "$INSTALL_SPEC"
else
  info "Installing from $INSTALL_SPEC"
  pipx install "$INSTALL_SPEC"
fi

info ""
info "Installed:"
"$APP_NAME" --version || fail "vaultsieve was installed but is not on PATH. Try: pipx ensurepath"
info ""
info "Run: vaultsieve"

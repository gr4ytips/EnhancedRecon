#!/usr/bin/env bash
# phase3_install.sh
# Installs dependencies for Phase 3 (Offline Forensics & Intelligence)
#
# REQUIRED (ReconAggregator artifacts):
#   - gitleaks
#   - osv-scanner
#
# Policy: install ALL Go tools into ~/go/bin only (no /usr/local/bin, no ~/.local/bin symlinks).

set -euo pipefail

VENV_DIR="${VENV_DIR:-$HOME/.venvs/phase3}"
GOPATH_DIR="${GOPATH:-$HOME/go}"
GOBIN_DIR="${GOBIN_DIR:-$HOME/go/bin}"

echo ">>> [Phase 3] Installing Dependencies..."

# 1) System tools (ExifTool required for metadata forensics)
sudo apt update
sudo apt install -y libimage-exiftool-perl || echo "[!] Failed to install exiftool via apt."

# 2) Ensure Go is present (required for gitleaks/osv-scanner)
if ! command -v go >/dev/null 2>&1; then
  echo ">>> Installing golang-go (required for gitleaks/osv-scanner)..."
  sudo apt install -y golang-go || {
    echo "[X] Failed to install golang-go. Install Go and re-run."
    exit 2
  }
fi

# Enforce Go install location
mkdir -p "$GOBIN_DIR"
export GOPATH="$GOPATH_DIR"
export GOBIN="$GOBIN_DIR"
export PATH="$GOBIN_DIR:$PATH"

echo ">>> Go env:"
echo "    GOPATH=$GOPATH"
echo "    GOBIN=$GOBIN"
echo "    go version: $(go version)"

install_go_tool() {
  local bin="$1"; shift
  if [ -x "$GOBIN_DIR/$bin" ]; then
    echo ">>> $bin already present: $GOBIN_DIR/$bin"
    return 0
  fi

  local ok=0
  for mod in "$@"; do
    echo ">>> go install $mod"
    if go install "$mod"; then
      ok=1
      break
    else
      echo "[!] go install failed: $mod"
    fi
  done

  if [ "$ok" -ne 1 ] || [ ! -x "$GOBIN_DIR/$bin" ]; then
    echo "[X] REQUIRED tool missing in $GOBIN_DIR: $bin"
    return 1
  fi
  echo ">>> $bin OK: $GOBIN_DIR/$bin"
  return 0
}

echo ">>> Installing REQUIRED Go tools into $GOBIN_DIR ..."

# gitleaks canonical module path (fixes your go.mod path mismatch error)
install_go_tool "gitleaks" \
  "github.com/zricethezav/gitleaks/v8@latest" \
  "github.com/zricethezav/gitleaks/v8@v8.30.0" || exit 2

# osv-scanner canonical module path
install_go_tool "osv-scanner" \
  "github.com/google/osv-scanner/cmd/osv-scanner@latest" || exit 2

echo ">>> gitleaks version:"
"$GOBIN_DIR/gitleaks" version || true
echo ">>> osv-scanner version:"
"$GOBIN_DIR/osv-scanner" --version || true

# 3) Python Virtual Environment
echo ">>> Setting up Python Venv at $VENV_DIR..."
if [ ! -d "$VENV_DIR" ]; then
  python3 -m venv "$VENV_DIR"
fi

# Activate
# shellcheck disable=SC1090
source "$VENV_DIR/bin/activate"
pip install --upgrade pip wheel

# 4) Python libraries
echo ">>> Installing Python Libraries..."
pip install \
  pandas \
  openpyxl \
  networkx \
  tldextract \
  colorama \
  python-magic \
  httpx

echo ""
echo ">>> Phase 3 Installation Complete."
echo "    - Venv: $VENV_DIR"
echo "    - ExifTool: $(command -v exiftool || echo MISSING)"
echo "    - gitleaks: $GOBIN_DIR/gitleaks"
echo "    - osv-scanner: $GOBIN_DIR/osv-scanner"
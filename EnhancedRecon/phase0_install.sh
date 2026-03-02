#!/usr/bin/env bash 
# phase0_install.sh
# Install dependencies for Phase 0 (Seeds -> Expansion -> Enum/Resolve -> IP assets)
#
# Creates a dedicated venv and installs Python libs used by:
#    - org_to_roots_seedgen.py
#    - expand_ips_to_domains_fcrdns_api_debug.py
#    - expand_and_enum_subs.py
#    - ip_assets_enrich.py
#
# UPDATED: Now automatically installs Go and Go-based recon tools.

set -euo pipefail

if [[ -z "${BASH_VERSION:-}" ]]; then
  echo "❌ Please run with bash: bash $0" >&2
  exit 2
fi

VENV_DIR="${VENV_DIR:-$HOME/.venvs/phase0}"
PY="${PYTHON_BIN:-python3}"
GO_INSTALL_DIR="/usr/local"
GO_BIN_PATH="$GO_INSTALL_DIR/go/bin"
USER_GO_BIN="${HOME}/go/bin"

echo "======================================================="
echo " Phase0 install"
echo " VENV_DIR : $VENV_DIR"
echo " PY       : $PY"
echo "======================================================="

command -v "$PY" >/dev/null 2>&1 || { echo "❌ python3 not found." >&2; exit 1; }

# 1. NEW: Install Go (if missing)
if ! command -v go >/dev/null 2>&1; then
    echo ">>> Go is missing. Installing latest stable Go..."
    LATEST_GO=$(curl -sL 'https://go.dev/VERSION?m=text' | head -n 1)
    curl -OL "https://go.dev/dl/${LATEST_GO}.linux-amd64.tar.gz"
    echo ">>> Extracting to $GO_INSTALL_DIR (requires sudo)..."
    sudo rm -rf "$GO_INSTALL_DIR/go"
    sudo tar -C "$GO_INSTALL_DIR" -xzf "${LATEST_GO}.linux-amd64.tar.gz"
    rm "${LATEST_GO}.linux-amd64.tar.gz"
    export PATH=$PATH:$GO_BIN_PATH
else
    echo "✅ Go found: $(go version)"
fi

# 2. Create venv (Original Logic)
if [[ ! -d "$VENV_DIR" ]]; then
  echo ">>> Creating venv: $VENV_DIR"
  "$PY" -m venv "$VENV_DIR"
else
  echo ">>> Using existing venv: $VENV_DIR"
fi

VENV_PY="$VENV_DIR/bin/python"
VENV_PIP="$VENV_DIR/bin/pip"

# Upgrade pip tooling
echo ">>> Upgrading pip/setuptools/wheel"
"$VENV_PY" -m pip install -U pip setuptools wheel

# Install python requirements (Expanded for your keys & xlsxwriter)
echo ">>> Installing Python deps (dnspython, requests, ipwhois, xlsxwriter, mmh3, shodan, censys)"
"$VENV_PIP" install -U \
    dnspython \
    requests \
    ipwhois \
    xlsxwriter \
    mmh3 \
    shodan \
    censys

# BinaryEdge Python client:
# - Correct pip package is: pybinaryedge
# - Install separately so Phase0 install doesn't hard-fail if this optional client changes.
echo ">>> Installing BinaryEdge client (pybinaryedge)"
"$VENV_PIP" install -U pybinaryedge || echo "[WARN] pybinaryedge install failed (optional). Continuing..."

echo
echo ">>> Verifying Python imports"
"$VENV_PY" - <<'PY'
import sys
mods = [
  "dns.resolver",
  "requests",
  "ipwhois",
  "xlsxwriter",
  "mmh3",
  "shodan",
  "censys",
  "pybinaryedge",
]
bad=[]
for m in mods:
    try:
        __import__(m.split(".")[0])
    except Exception as e:
        bad.append((m, repr(e)))
if bad:
    print("❌ Missing imports:")
    for m,e in bad:
        print(" -", m, e)
    sys.exit(1)
print("✅ Python deps OK")
PY

# 3. NEW: Automated installation of Go tools
echo
echo ">>> Installing/Updating Go Recon Tools..."
export PATH=$PATH:$USER_GO_BIN
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/unfurl@latest
go install -v github.com/owasp-amass/amass/v4/...@latest

echo
echo ">>> Checking external tools"
need=("dnsx" "subfinder" "assetfinder" "amass" "httpx")
for t in "${need[@]}"; do
  if command -v "$t" >/dev/null 2>&1; then
    echo " - $t: FOUND ($(command -v "$t"))"
  else
    echo " - $t: MISSING"
  fi
done

# 4. NEW: Kali PATH Persistence
echo
echo ">>> Updating Shell Profile for Persistence..."
GO_PATHS='export PATH=$PATH:/usr/local/go/bin:~/go/bin'
for profile in ~/.bashrc ~/.zshrc; do
    if [ -f "$profile" ]; then
        grep -qF "$GO_PATHS" "$profile" || echo "$GO_PATHS" >> "$profile"
        echo " ✅ Added Go paths to $profile"
    fi
done

echo
echo "✅ Phase0 install complete."
echo "Next: source ~/.bashrc (or ~/.zshrc) AND then ./phase0_precheck.sh"
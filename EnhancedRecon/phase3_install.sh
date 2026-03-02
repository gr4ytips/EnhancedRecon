#!/usr/bin/env bash
# phase3_install.sh
# Installs dependencies for Phase 3 (Offline Forensics & Intelligence)

set -euo pipefail

# Config
VENV_DIR="${VENV_DIR:-$HOME/.venvs/phase3}"

echo ">>> [Phase 3] Installing Dependencies..."

# 1. System Tools (ExifTool is required for metadata)
sudo apt update
sudo apt install -y libimage-exiftool-perl || echo "[!] Failed to install exiftool via apt."

# 2. Python Virtual Environment
echo ">>> Setting up Python Venv at $VENV_DIR..."
if [ ! -d "$VENV_DIR" ]; then
    python3 -m venv "$VENV_DIR"
fi

# Activate
source "$VENV_DIR/bin/activate"
pip install --upgrade pip wheel

# 3. Install Libraries
# We need libraries for data processing (CSV/Excel) and graph analysis
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
echo "    - System Tool: ExifTool"
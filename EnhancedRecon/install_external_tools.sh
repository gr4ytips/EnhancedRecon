#!/usr/bin/env bash
set -euo pipefail

echo "[*] Updating system and installing basic dependencies..."
sudo apt update
sudo apt install -y curl jq git golang-go

export GOPATH="${GOPATH:-$HOME/go}"
export PATH="$HOME/go/bin:$PATH"

# Persist PATH safely (no duplicates)
add_path_line() {
  local profile="$1"
  local line='export PATH="$HOME/go/bin:$PATH"'
  [[ -f "$profile" ]] || return 0
  grep -qF "$line" "$profile" || echo "$line" >> "$profile"
}

add_path_line "$HOME/.bashrc"
add_path_line "$HOME/.zshrc"

echo "[*] Installing Go tools (@latest)..."
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/owasp-amass/amass/v4/...@latest

echo
echo "[*] Verifying tools..."
for t in dnsx subfinder httpx assetfinder amass; do
  if command -v "$t" >/dev/null 2>&1; then
    echo " - $t: OK ($(command -v "$t"))"
  else
    echo " - $t: MISSING"
  fi
done

echo
echo "✅ Bootstrap complete."
echo "👉 Run: source ~/.bashrc  (or source ~/.zshrc)"
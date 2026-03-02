#!/usr/bin/env bash
set -euo pipefail

# Configurable
VENV_DIR="${VENV_DIR:-$HOME/.venvs/phase1}"
TOOLS_DIR="${TOOLS_DIR:-$HOME/tools}"
GOPATH="${GOPATH:-$HOME/go}"

echo "== apt base =="
sudo apt update
# Added build-essential & python3-dev for compiling python extensions (like mmh3)
sudo apt install -y \
  curl jq git build-essential \
  python3 python3-pip python3-venv python3-dev \
  golang-go \
  amass subfinder || true   # Kali often has these; ignore if not found

mkdir -p "$TOOLS_DIR" "$GOPATH/bin"

# Ensure PATH for current shell session
case ":$PATH:" in *":$GOPATH/bin:"*) :;; *) export PATH="$PATH:$GOPATH/bin";; esac

# Persist PATH for future shells (zsh/bash)
SHELL_RC="$HOME/.zshrc"
[ -n "${BASH_VERSION:-}" ] && SHELL_RC="$HOME/.bashrc"
if ! grep -q 'export GOPATH=' "$SHELL_RC" 2>/dev/null; then
  {
    echo "export GOPATH=\${GOPATH:-$GOPATH}"
    echo 'export PATH="$PATH:$GOPATH/bin"'
  } >> "$SHELL_RC"
fi

echo "== Go tools =="
# ProjectDiscovery / tomnomnom / lc
go install github.com/projectdiscovery/httpx/cmd/httpx@latest
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest || true
go install github.com/tomnomnom/waybackurls@latest
go install github.com/lc/gau/v2/cmd/gau@latest
go install github.com/tomnomnom/unfurl@latest
go install github.com/tomnomnom/assetfinder@latest
go install github.com/tomnomnom/anew@latest
go install github.com/tomnomnom/qsreplace@latest

# Amass via Go (fallback if apt’s amass missing or old)
if ! command -v amass >/dev/null 2>&1; then
  go install github.com/owasp-amass/amass/v4/...@latest
fi

echo "== github-subdomains (build from source) =="
GHS_DIR="$TOOLS_DIR/github-subdomains"
if [ ! -d "$GHS_DIR/.git" ]; then
  git clone https://github.com/gwen001/github-subdomains "$GHS_DIR"
fi
(
  cd "$GHS_DIR"
  # rebuild for local arch (avoid foreign prebuilt)
  rm -f github-subdomains || true
  go mod tidy
  GO111MODULE=on CGO_ENABLED=0 go build -o github-subdomains .
)
sudo ln -sf "$GHS_DIR/github-subdomains" /usr/local/bin/github-subdomains
chmod +x "$GHS_DIR/github-subdomains"

echo "== Python venv for Phase-1 scripts =="
mkdir -p "$(dirname "$VENV_DIR")"
if [ ! -x "$VENV_DIR/bin/python" ]; then
  python3 -m venv "$VENV_DIR"
fi
"$VENV_DIR/bin/python" -m pip install --upgrade pip wheel

# Minimal, safe deps our Phase-1 scripts commonly need
# ADDED: mmh3 (favicons), warcio (archive parsing)
"$VENV_DIR/bin/pip" install \
  aiohttp aiofiles ijson \
  tldextract requests \
  PyYAML \
  mmh3 warcio

# (Optional) If our Phase-1 repo has a requirements.txt, install it too:
REQS="${REQS:-}"
if [ -n "$REQS" ] && [ -f "$REQS" ]; then
  "$VENV_DIR/bin/pip" install -r "$REQS"
fi

echo
echo "== Summary =="
command -v httpx && httpx -version || true
command -v subfinder && subfinder -version || true
command -v waybackurls >/dev/null && echo "waybackurls: OK"
command -v gau >/dev/null && echo "gau: OK"
command -v unfurl >/dev/null && echo "unfurl: OK"
command -v assetfinder >/dev/null && echo "assetfinder: OK"
command -v amass >/dev/null && echo "amass: OK"
command -v github-subdomains >/dev/null && echo "github-subdomains: OK"
echo "venv: $VENV_DIR (activate with: source \"$VENV_DIR/bin/activate\")"

echo
echo "Done. Open a new shell or run:"
echo "  export PATH=\"\$PATH:$GOPATH/bin\""
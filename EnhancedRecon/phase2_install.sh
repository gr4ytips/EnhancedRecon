#!/usr/bin/env bash
set -euo pipefail

# phase2_install.sh
# NOTE: This is a "full workstation" installer (apt + go + pip + npm + wrappers).
# You can reduce weight by toggles:
#   INSTALL_SCANNERS=no        # skip heavy web scanners (zaproxy/nikto/wapiti/skipfish)
#   INSTALL_OFFLINE_TOOLS=no   # skip some offline tools (trufflehog via apt)
INSTALL_SCANNERS="${INSTALL_SCANNERS:-yes}"
INSTALL_OFFLINE_TOOLS="${INSTALL_OFFLINE_TOOLS:-yes}"

_norm_yesno() {
  local v="${1:-}"; v="${v,,}"
  case "$v" in 1|y|yes|true|on) echo yes ;; *) echo no ;; esac
}
INSTALL_SCANNERS="$(_norm_yesno "$INSTALL_SCANNERS")"
INSTALL_OFFLINE_TOOLS="$(_norm_yesno "$INSTALL_OFFLINE_TOOLS")"

# Resolve ROOT/TOOLS if not provided (so RULES_FILE can default correctly)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -d "$SCRIPT_DIR/tools/custom-recon-tools_EXPANDED" ]]; then
  ROOT="${ROOT:-$SCRIPT_DIR}"
elif [[ "$(basename "$SCRIPT_DIR")" == "custom-recon-tools_EXPANDED" && -d "$SCRIPT_DIR" ]]; then
  ROOT="${ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
elif [[ -d "$SCRIPT_DIR/../tools/custom-recon-tools_EXPANDED" ]]; then
  ROOT="${ROOT:-$(cd "$SCRIPT_DIR/.." && pwd)}"
else
  ROOT="${ROOT:-$SCRIPT_DIR}"
fi
TOOLS="${TOOLS:-$ROOT/tools/custom-recon-tools_EXPANDED}"

# ---- Config ----
VENV_DIR="${VENV_DIR:-$HOME/.venvs/phase2}"
TOOLS_DIR="${TOOLS_DIR:-$HOME/tools}"
GOPATH="${GOPATH:-$HOME/go}"
NUCLEI_TEMPLATES_DIR="${NUCLEI_TEMPLATES_DIR:-$HOME/nuclei-templates}"
SKIPFISH_WL_DEFAULT="/usr/share/skipfish/dictionaries/medium.wl"

echo "== apt base =="
sudo apt update

APT_BASE=(
  curl jq git build-essential libffi-dev
  python3 python3-venv python3-pip
  golang-go
  nodejs npm
  whatweb
)
sudo apt install -y "${APT_BASE[@]}"

if [[ "$INSTALL_SCANNERS" == "yes" ]]; then
  echo "== apt scanners (heavy) =="
  sudo apt install -y zaproxy nikto wapiti skipfish || true
else
  echo "== apt scanners skipped (INSTALL_SCANNERS=no) =="
fi

if [[ "$INSTALL_OFFLINE_TOOLS" == "yes" ]]; then
  echo "== apt offline tools =="
  sudo apt install -y trufflehog || true
else
  echo "== apt offline tools skipped (INSTALL_OFFLINE_TOOLS=no) =="
fi

# make dirs
mkdir -p "$TOOLS_DIR" "$GOPATH/bin"
case ":$PATH:" in *":$GOPATH/bin:"*) :;; *) export PATH="$PATH:$GOPATH/bin";; esac

# ---- Go tools (Phase-2) ----
echo "== Go tools =="
go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest || true
go install github.com/projectdiscovery/katana/cmd/katana@latest || true

if ! command -v gf >/dev/null 2>&1; then
  go install github.com/tomnomnom/gf@latest || true
fi

# ---- Nuclei templates ----
echo "== Nuclei templates =="
if [ -d "$NUCLEI_TEMPLATES_DIR/.git" ]; then
  git -C "$NUCLEI_TEMPLATES_DIR" pull --ff-only || true
else
  git clone https://github.com/projectdiscovery/nuclei-templates "$NUCLEI_TEMPLATES_DIR"
fi

# ---- Python venv for Phase-2 helpers (UCA + JS tools) ----
echo "== Python venv =="
mkdir -p "$(dirname "$VENV_DIR")"
[ -x "$VENV_DIR/bin/python" ] || python3 -m venv "$VENV_DIR"
"$VENV_DIR/bin/python" -m pip install -U pip wheel

# Core libs used by harvest_and_scan.py (and UCA auto-heal)
"$VENV_DIR/bin/pip" install -U   aiohttp aiofiles ijson PyYAML   semgrep   wappalyzer   sourcemap   playwright   arjun   requests urllib3 beautifulsoup4 lxml colorama

# Install Playwright Browsers (for DOM scanning)
echo "== Playwright Browsers =="
"$VENV_DIR/bin/playwright" install chromium

# LinkFinder via pip+git (packaged with console script)
"$VENV_DIR/bin/pip" install -U   git+https://github.com/GerbenJavado/LinkFinder.git

# ---- SecretFinder (clone + wrapper) ----
echo "== SecretFinder (git clone + wrapper) =="
SF_DIR="$TOOLS_DIR/SecretFinder"
if [ ! -d "$SF_DIR/.git" ]; then
  git clone https://github.com/m4ll0k/SecretFinder "$SF_DIR"
else
  git -C "$SF_DIR" pull --ff-only || true
fi

# ---- ParamSpider (clone + wrapper) ----
echo "== ParamSpider (git clone + wrapper) =="
PS_DIR="$TOOLS_DIR/ParamSpider"
if [ ! -d "$PS_DIR/.git" ]; then
  git clone https://github.com/devanshbatham/ParamSpider "$PS_DIR"
else
  git -C "$PS_DIR" pull --ff-only || true
fi
if [ -f "$PS_DIR/requirements.txt" ]; then
  "$VENV_DIR/bin/pip" install -r "$PS_DIR/requirements.txt"
fi

# ---- Node global: retire.js ----
echo "== retire.js (npm) =="
sudo npm install -g retire

# ---- Wrappers into /usr/local/bin ----
echo "== Wrappers =="

sudo tee /usr/local/bin/linkfinder >/dev/null <<EOF
#!/usr/bin/env bash
exec "$VENV_DIR/bin/linkfinder" "\$@"
EOF
sudo chmod +x /usr/local/bin/linkfinder

sudo tee /usr/local/bin/SecretFinder >/dev/null <<EOF
#!/usr/bin/env bash
exec "$VENV_DIR/bin/python" "$SF_DIR/SecretFinder.py" "\$@"
EOF
sudo chmod +x /usr/local/bin/SecretFinder

sudo tee /usr/local/bin/paramspider >/dev/null <<EOF
#!/usr/bin/env bash
cd "$PS_DIR"
exec "$VENV_DIR/bin/python" "$PS_DIR/main.py" "\$@"
EOF
sudo chmod +x /usr/local/bin/paramspider

sudo tee /usr/local/bin/arjun >/dev/null <<EOF
#!/usr/bin/env bash
exec "$VENV_DIR/bin/arjun" "\$@"
EOF
sudo chmod +x /usr/local/bin/arjun

# Python wappalyzer CLI wrapper (keeps consistency: no npm wappalyzer required)
sudo tee /usr/local/bin/wappalyzer >/dev/null <<EOF
#!/usr/bin/env bash
exec "$VENV_DIR/bin/wappalyzer" "\$@"
EOF
sudo chmod +x /usr/local/bin/wappalyzer

# ProjectDiscovery httpx wrapper (if not already created in Phase-1)
if [ ! -x /usr/local/bin/httpx-pd ] && [ -x "$HOME/go/bin/httpx" ]; then
  sudo tee /usr/local/bin/httpx-pd >/dev/null <<'EOF'
#!/usr/bin/env bash
exec "$HOME/go/bin/httpx" "$@"
EOF
  sudo chmod +x /usr/local/bin/httpx-pd
fi

# ---- Skipfish wordlist sanity ----
if [ -f "$SKIPFISH_WL_DEFAULT" ]; then
  echo "skipfish wordlist: $SKIPFISH_WL_DEFAULT"
else
  echo "⚠ Could not find $SKIPFISH_WL_DEFAULT — pass --skipfish-wordlist explicitly if you use skipfish."
fi

echo
echo "== Summary =="
command -v linkfinder   >/dev/null && echo "linkfinder:   $(command -v linkfinder)"
command -v SecretFinder >/dev/null && echo "SecretFinder: $(command -v SecretFinder)"
command -v paramspider  >/dev/null && echo "paramspider:  $(command -v paramspider)"
command -v arjun        >/dev/null && echo "arjun:        $(command -v arjun)"
command -v retire       >/dev/null && echo "retire:       $(command -v retire)"
command -v wappalyzer   >/dev/null && echo "wappalyzer:   $(command -v wappalyzer)"
command -v whatweb      >/dev/null && echo "whatweb:      $(command -v whatweb)"
command -v nuclei       >/dev/null && nuclei -version || true
[ -x "$HOME/go/bin/katana" ] && echo "katana bin:   $HOME/go/bin/katana"
[ -d "$NUCLEI_TEMPLATES_DIR" ] && echo "nuclei templates: $NUCLEI_TEMPLATES_DIR"
command -v nikto        >/dev/null && echo "nikto:        $(command -v nikto)"
command -v wapiti       >/dev/null && echo "wapiti:       $(command -v wapiti)"
command -v zaproxy      >/dev/null && echo "zaproxy:      $(command -v zaproxy)"
command -v skipfish     >/dev/null && echo "skipfish:     $(command -v skipfish)"
[ -x /usr/local/bin/httpx-pd ] && echo "httpx-pd:     /usr/local/bin/httpx-pd"

echo
echo "venv: $VENV_DIR (activate: source \"$VENV_DIR/bin/activate\")"
echo "Tip: ensure PATH contains: \$HOME/go/bin  and  $VENV_DIR/bin"

# ---------------------------------------------------------
# Extra: semgrep, gf, gf patterns, and default JS rules
# ---------------------------------------------------------
GF_DIR="${GF_DIR:-$HOME/.gf}"
RULES_FILE="${RULES_FILE:-$TOOLS/advanced_js_rules.yaml}"
mkdir -p "$(dirname "$RULES_FILE")"

echo "[*] Ensuring semgrep is installed in the venv..."
"$VENV_DIR/bin/python" -m pip install -U semgrep >/dev/null

echo "[*] Ensuring gf is installed (tomnomnom/gf)..."
if ! command -v gf >/dev/null 2>&1; then
  if command -v go >/dev/null 2>&1; then
    go install github.com/tomnomnom/gf@latest
    export PATH="$PATH:$HOME/go/bin"
  else
    echo "⚠️  go not found; cannot install gf automatically. Install Go, then: go install github.com/tomnomnom/gf@latest" >&2
  fi
fi

echo "[*] Ensuring gf patterns exist in: $GF_DIR"
mkdir -p "$GF_DIR"
if ! ls -1 "$GF_DIR"/*.json >/dev/null 2>&1; then
  if command -v git >/dev/null 2>&1; then
    tmp="$(mktemp -d)"
    git clone --depth 1 https://github.com/1ndianl33t/Gf-Patterns "$tmp/Gf-Patterns" >/dev/null 2>&1 || true
    if ls -1 "$tmp/Gf-Patterns"/*.json >/dev/null 2>&1; then
      cp -n "$tmp/Gf-Patterns"/*.json "$GF_DIR/" || true
      echo "    - Installed gf patterns from 1ndianl33t/Gf-Patterns"
    else
      echo "⚠️  Could not fetch patterns repo. You can add patterns manually under $GF_DIR" >&2
    fi
    rm -rf "$tmp" || true
  else
    echo "⚠️  git not found; cannot auto-fetch gf patterns. Put pattern JSON files under $GF_DIR" >&2
  fi
fi

echo "[*] Ensuring advanced semgrep rules exist: $RULES_FILE"
if [[ ! -f "$RULES_FILE" ]]; then
  cat > "$RULES_FILE" <<'YAML'
rules:
  - id: js-hardcoded-aws-key
    message: Possible AWS Access Key ID in JavaScript/source.
    languages: [javascript, typescript]
    severity: WARNING
    pattern-regex: '(?i)\bAKIA[0-9A-Z]{16}\b'

  - id: js-hardcoded-slack-token
    message: Possible Slack token in JavaScript/source.
    languages: [javascript, typescript]
    severity: WARNING
    pattern-regex: '(xox[baprs]-[0-9A-Za-z-]{10,48})'

  - id: js-private-key
    message: Possible embedded private key.
    languages: [javascript, typescript]
    severity: ERROR
    pattern-regex: '-----BEGIN (RSA|EC|DSA|OPENSSH) PRIVATE KEY-----'

  - id: js-github-token
    message: Possible GitHub token.
    languages: [javascript, typescript]
    severity: WARNING
    pattern-regex: '(?i)\bgh[pousr]_[A-Za-z0-9]{36,255}\b'
YAML
  echo "    - Wrote default rules: $RULES_FILE"
fi

# ---------------------------------------------------------
# UCA / code_analyzer offline semgrep ruleset (pre-download)
# Prevents interactive prompt:
#   ~/.local/share/code_analyzer/semgrep-rules
# ---------------------------------------------------------
UCA_SEMGREP_RULES_DIR="${UCA_SEMGREP_RULES_DIR:-$HOME/.local/share/code_analyzer/semgrep-rules}"
mkdir -p "$(dirname "$UCA_SEMGREP_RULES_DIR")"

echo "[*] Ensuring UCA offline semgrep ruleset exists: $UCA_SEMGREP_RULES_DIR"
if [[ -d "$UCA_SEMGREP_RULES_DIR/.git" ]]; then
  git -C "$UCA_SEMGREP_RULES_DIR" pull --ff-only || true
elif [[ -d "$UCA_SEMGREP_RULES_DIR" ]] && ls -1 "$UCA_SEMGREP_RULES_DIR" >/dev/null 2>&1; then
  echo "    - Found existing ruleset folder (non-git). Keeping as-is."
else
  git clone --depth 1 https://github.com/returntocorp/semgrep-rules "$UCA_SEMGREP_RULES_DIR" \
    || echo "[WARN] Failed to download semgrep-rules. UCA may prompt/abort if semgrep scanning is enabled."
fi

echo "✅ phase2_install: done"

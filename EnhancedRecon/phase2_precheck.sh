#!/usr/bin/env bash
set -euo pipefail

# phase2_precheck.sh
# Phase-2 environment precheck (binaries + venv + optional auto-fix).
#
# IMPORTANT SAFETY:
# - Auto-fix will run apt/go/npm installs. It is OFF by default.
#   Enable by exporting: AUTO_FIX=yes

AUTO_FIX="${AUTO_FIX:-no}"
_norm_yesno() {
  local v="${1:-}"; v="${v,,}"
  case "$v" in 1|y|yes|true|on) echo yes ;; *) echo no ;; esac
}
AUTO_FIX="$(_norm_yesno "$AUTO_FIX")"

# -------- CONFIG ----------
VENV_BIN="${VENV_BIN:-$HOME/.venvs/phase2/bin}"

# Resolve ROOT/TOOLS automatically (so this works whether called standalone or from runner)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -d "$SCRIPT_DIR/tools/custom-recon-tools_EXPANDED" ]]; then
  ROOT="${ROOT:-$SCRIPT_DIR}"
else
  ROOT="${ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
fi
TOOLS="${TOOLS:-$ROOT/tools/custom-recon-tools_EXPANDED}"

VENV_DIR="${VENV_DIR:-$(cd "$VENV_BIN/.." && pwd)}"

# Feature flags (set EXPECT_*=no to skip check)
EXPECT_JS_TOOLS="${EXPECT_JS_TOOLS:-yes}"
EXPECT_UNFURL="${EXPECT_UNFURL:-no}"
EXPECT_OFFLINE="${EXPECT_OFFLINE:-yes}"
EXPECT_SCANNERS="${EXPECT_SCANNERS:-no}"
EXPECT_DYNAMIC="${EXPECT_DYNAMIC:-yes}"
EXPECT_DISCOVERY="${EXPECT_DISCOVERY:-yes}"

# -------- helpers ----------
ok()   { printf "✅ %s
" "$*"; }
warn() { printf "⚠️  %s
" "$*" >&2; }
bad()  { printf "❌ %s
" "$*" >&2; }

need_bin() {
  if command -v "$1" >/dev/null 2>&1; then ok "found $1 ($(command -v "$1"))"; return 0; else bad "missing $1"; return 1; fi
}

need_py_import() {
  "$VENV_BIN/python" - <<'PY' "$1" >/dev/null 2>&1 && ok "python import $1 OK" || { bad "python import $1 FAILED"; return 1; }
import importlib, sys
importlib.import_module(sys.argv[1])
PY
}

is_pd_httpx() {
  local bin="$1"
  [[ -z "$bin" ]] && return 1
  [[ ! -x "$bin" ]] && return 1
  "$bin" -version >/dev/null 2>&1 && return 0
  "$bin" --version >/dev/null 2>&1 && return 0
  local h
  h="$("$bin" -h 2>&1 || true)"
  echo "$h" | grep -q -- "-silent" || return 1
  echo "$h" | grep -q -- "-l"      || return 1
  return 0
}

echo "== Phase-2 core checks =="

if [[ -x "$VENV_BIN/python" ]]; then
  ok "venv python at $VENV_BIN/python"
else
  bad "venv not found -> create: python3 -m venv $HOME/.venvs/phase2"
fi

[[ -x "$VENV_BIN/pip" ]] && ok "venv pip present" || bad "venv pip missing -> run: $VENV_BIN/python -m ensurepip && $VENV_BIN/pip install --upgrade pip"

need_py_import "aiohttp"
need_py_import "aiofiles"
need_py_import "sourcemap"

need_bin curl || true
need_bin jq   || true

HTTPX_PATH="$(command -v httpx 2>/dev/null || true)"
HTTPX_PD_PATH="$(command -v httpx-pd 2>/dev/null || true)"
if [[ -n "$HTTPX_PD_PATH" ]]; then
  ok "httpx-pd wrapper present ($HTTPX_PD_PATH)"
fi
if [[ -n "$HTTPX_PATH" ]]; then
  if is_pd_httpx "$HTTPX_PATH"; then
    ok "httpx looks like ProjectDiscovery ($HTTPX_PATH)"
  else
    warn "httpx is present but does NOT look like ProjectDiscovery (possible python httpx CLI): $HTTPX_PATH"
    warn "Fix: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
  fi
else
  warn "httpx not found (alive URL steps may be skipped unless you set HTTPX_BIN)"
fi

echo "== PATH sanity =="
echo "$PATH" | grep -q "$HOME/go/bin" && ok "GOPATH bin on PATH" || warn 'add to PATH: echo '''export PATH="$HOME/go/bin:$PATH"''' >> ~/.bashrc'
echo "$PATH" | grep -q "$VENV_BIN"    && ok "venv bin on PATH"   || warn "add venv bin to PATH: echo 'export PATH="$VENV_BIN:\$PATH"' >> ~/.bashrc"

if [[ "$EXPECT_DYNAMIC" == "yes" ]]; then
  echo "== Dynamic Analysis =="
  need_bin katana || warn "Install: go install github.com/projectdiscovery/katana/cmd/katana@latest"
  need_py_import "playwright" || bad "Playwright lib missing. Run phase2_install.sh"

  echo -n "Playwright browsers check: "
  if "$VENV_BIN/python" - <<'PY' >/dev/null 2>&1; then
from playwright.sync_api import sync_playwright
with sync_playwright() as p:
    b = p.chromium.launch(headless=True)
    b.close()
PY
    ok "chromium launch OK"
  else
    bad "chromium launch FAILED (browsers likely missing). Run: $VENV_BIN/playwright install chromium"
  fi
fi

if [[ "$EXPECT_DISCOVERY" == "yes" ]]; then
  echo "== Discovery Tools =="
  need_bin arjun       || warn "Install: pip install arjun (inside venv) or run phase2_install.sh"
  need_bin paramspider || warn "Install via phase2_install.sh (wrapper /usr/local/bin/paramspider)"
fi

if [[ "$EXPECT_JS_TOOLS" == "yes" ]]; then
  echo "== JS tools =="
  need_bin linkfinder   || warn "Install LinkFinder into venv and wrapper /usr/local/bin/linkfinder"
  need_bin SecretFinder || warn "Install SecretFinder and wrapper /usr/local/bin/SecretFinder"
fi

if [[ "$EXPECT_UNFURL" == "yes" ]]; then
  echo "== Unfurl =="
  need_bin unfurl || warn "Install: go install github.com/tomnomnom/unfurl@latest"
fi

if [[ "$EXPECT_OFFLINE" == "yes" ]]; then
  echo "== Offline analyzers =="
  need_bin retire     || warn "Install: npm i -g retire"
  need_bin trufflehog || warn "Install: go install github.com/trufflesecurity/trufflehog/v3@latest (or apt trufflehog)"
  need_bin wappalyzer || warn "Install: phase2_install.sh creates /usr/local/bin/wappalyzer wrapper (python CLI)"
  need_bin whatweb    || warn "Install: sudo apt install -y whatweb"

  GF_DIR="${GF_DIR:-$HOME/.gf}"
  if ls -1 "$GF_DIR"/*.json >/dev/null 2>&1; then
    ok "GF patterns found in $GF_DIR"
  else
    warn "GF patterns missing/empty in $GF_DIR (needed for some secret scans)"
  fi
fi

if [[ "$EXPECT_SCANNERS" == "yes" ]]; then
  echo "== Web scanners =="
  need_bin nuclei   || warn "Install: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
  need_bin nikto    || warn "Install: sudo apt install -y nikto"
  need_bin wapiti   || warn "Install: sudo apt install -y wapiti"
  need_bin zaproxy  || warn "Install: sudo apt install -y zaproxy"
  need_bin skipfish || warn "Install: sudo apt install -y skipfish"
fi

echo "== Extra checks: semgrep, gf patterns, advanced rules =="

GF_DIR="${GF_DIR:-$HOME/.gf}"
RULES_FILE="${RULES_FILE:-$TOOLS/advanced_js_rules.yaml}"

need_fix=0

if [[ ! -x "$VENV_DIR/bin/semgrep" ]]; then
  bad "Missing semgrep in venv: $VENV_DIR/bin/semgrep"
  need_fix=1
else
  ok "semgrep present"
fi

if ! command -v gf >/dev/null 2>&1; then
  warn "gf binary not found (optional but recommended)."
  need_fix=1
else
  ok "gf present"
fi

mkdir -p "$GF_DIR"
if ! ls -1 "$GF_DIR"/*.json >/dev/null 2>&1; then
  bad "GF patterns missing in: $GF_DIR (need *.json)"
  need_fix=1
else
  ok "GF patterns present"
fi

if [[ ! -f "$RULES_FILE" ]]; then
  bad "Missing semgrep rules: $RULES_FILE"
  need_fix=1
else
  ok "Semgrep rules present ($RULES_FILE)"
fi

INSTALL_SCRIPT_FALLBACK="$SCRIPT_DIR/phase2_install.sh"
[[ -f "$INSTALL_SCRIPT_FALLBACK" ]] || INSTALL_SCRIPT_FALLBACK="$ROOT/phase2_install.sh"

if [[ "$need_fix" -eq 1 ]]; then
  echo "---------------------------------------------------------"
  echo "Some Phase2 prerequisites are missing."
  echo "AUTO_FIX=$AUTO_FIX"
  echo "---------------------------------------------------------"
  if [[ "$AUTO_FIX" == "yes" ]]; then
    if [[ -f "$INSTALL_SCRIPT_FALLBACK" ]]; then
      echo "[*] Attempting auto-fix via: $INSTALL_SCRIPT_FALLBACK"
      bash "$INSTALL_SCRIPT_FALLBACK" || true
    else
      bad "Install script not found: $INSTALL_SCRIPT_FALLBACK"
      exit 1
    fi
  else
    warn "Auto-fix disabled. Re-run with: AUTO_FIX=yes bash phase2_precheck.sh"
  fi
fi

if [[ "$AUTO_FIX" == "yes" ]]; then
  if [[ ! -x "$VENV_DIR/bin/semgrep" ]]; then
    bad "semgrep still missing after auto-fix. Aborting."
    exit 1
  fi
  if [[ ! -f "$RULES_FILE" ]]; then
    bad "rules file still missing after auto-fix. Aborting."
    exit 1
  fi
fi

echo "== Done. Any ❌ above needs fixing before running Phase-2 Enhanced =="

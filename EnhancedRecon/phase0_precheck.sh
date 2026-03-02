#!/usr/bin/env bash
# phase0_precheck.sh
# Sanity checks for Phase 0 toolchain (Seeds -> Expansion -> Enum/Resolve -> IP assets)

set -euo pipefail

if [[ -z "${BASH_VERSION:-}" ]]; then
  echo "❌ Please run with bash: bash $0" >&2
  exit 2
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOOLS_DIR="${TOOLS_DIR:-$SCRIPT_DIR/tools/custom-recon-tools_EXPANDED}"

VENV_DIR="${VENV_DIR:-$HOME/.venvs/phase0}"
VENV_PY="$VENV_DIR/bin/python"

echo "======================================================="
echo " Phase0 precheck"
echo " TOOLS_DIR : $TOOLS_DIR"
echo " VENV_DIR  : $VENV_DIR"
echo "======================================================="

fail=0

# --- Python / venv ---
if ! command -v python3 >/dev/null 2>&1; then
  echo "❌ python3 not found"
  fail=1
else
  echo "[*] python3: $(command -v python3)"
fi

if [[ ! -x "$VENV_PY" ]]; then
  echo "❌ venv python missing: $VENV_PY"
  echo "   Run: ./phase0_install.sh"
  fail=1
else
  echo "[*] venv python: $VENV_PY"
fi

# --- Required scripts ---
req_scripts=(
  "org_to_roots_seedgen.py"
  "expand_ips_to_domains_fcrdns_api_debug.py"
  "expand_and_enum_subs.py"
  "ip_assets_enrich.py"
  "scope_filter.py"
)

echo
echo ">>> Checking required scripts"
for s in "${req_scripts[@]}"; do
  if [[ -f "$TOOLS_DIR/$s" ]]; then
    echo " - $s: OK"
  else
    echo " - $s: MISSING ($TOOLS_DIR/$s)"
    fail=1
  fi
done

# --- Python imports ---
if [[ -x "$VENV_PY" ]]; then
  echo
  echo ">>> Checking Python imports in venv"
  exit_code=0
  "$VENV_PY" - <<'PY' || exit_code=$?
import sys
need = ["dns.resolver", "requests", "ipwhois", "xlsxwriter"]
missing=[]
for m in need:
    try:
        __import__(m.split(".")[0])
    except Exception as e:
        missing.append((m, repr(e)))
if missing:
    print("❌ Missing deps:")
    for m,e in missing:
        print(" -", m, e)
    sys.exit(1)
print("✅ Python deps OK")
PY
  if [[ "${exit_code:-0}" -ne 0 ]]; then
    fail=1
  fi
fi

# --- External tools ---
echo
echo ">>> Checking external tools"
check_tool() {
  local name="$1"
  if command -v "$name" >/dev/null 2>&1; then
    echo " - $name: FOUND ($(command -v "$name"))"
    return 0
  else
    echo " - $name: MISSING"
    return 1
  fi
}
# dnsx is required if you run expand_and_enum_subs.py with --resolve yes
check_tool dnsx || echo "   (Required for --resolve yes)"
# Enumerators used by expand_ips_to_domains_fcrdns_api_debug.py (when --enum-domains yes)
enum_ok=0
for t in subfinder assetfinder amass; do
  if check_tool "$t"; then enum_ok=1; fi
done
if [[ "$enum_ok" -eq 0 ]]; then
  echo "❌ None of subfinder/assetfinder/amass found (required if you enable --enum-domains yes)" >&2
  fail=1
fi
# Optional helpers
check_tool httpx || true
check_tool jq || true
# --- API keys (optional) ---
echo
echo ">>> API keys (optional, enable enrichment sources)"
opt_keys=("SHODAN_API_KEY" "SECURITYTRAILS_KEY" "CENSYS_API_KEY" "CENSYS_API_ID" "CENSYS_API_SECRET" "IPINFO_API_KEY" "HACKERTARGET_API_KEY" "GITHUB_TOKEN" "URLSCAN_API_KEY")
for k in "${opt_keys[@]}"; do
  if [[ -n "${!k:-}" ]]; then
    echo " - $k: SET"
  else
    echo " - $k: (not set)"
  fi
done
# --- Disk space ---
echo
echo ">>> Storage"
df -h . | awk 'NR==1 || NR==2 {print " " $0}'

echo
if [[ "$fail" -ne 0 ]]; then
  echo "❌ Phase0 precheck FAILED"
  exit 1
fi

echo "✅ Phase0 precheck OK"
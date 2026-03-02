#!/usr/bin/env bash
# phase1_precheck.sh (v1.6)
# Verifies environment health: Binaries, Python Venv, Critical Libs (mmh3/warcio), and API Keys.
# Also validates that httpx is ProjectDiscovery httpx (not python httpx CLI).

set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
NC='\033[0m'

VENV_DIR="${VENV_DIR:-$HOME/.venvs/phase1}"
PYTHON="$VENV_DIR/bin/python"

echo "=== Phase 1 Environment Pre-Check ==="

# 1. Check Python Venv & Core Libs
echo -n "[*] Checking Python Virtual Environment ($VENV_DIR)... "
if [ -x "$PYTHON" ]; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}MISSING${NC}"
    echo "    -> Please run 'bash phase1_install.sh' to create it."
    exit 1
fi

echo -n "[*] Checking Critical Python Libraries (mmh3, warcio, requests, idna)... "
if "$PYTHON" -c "import mmh3, warcio, requests, idna" 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
    echo "    -> Missing libraries. Please run: $VENV_DIR/bin/pip install mmh3 warcio requests idna"
    echo "    -> Note: 'mmh3' may require build-essential and python3-dev."
fi

# 2. Check External Tools
echo "[*] Checking External Tools:"
MISSING_TOOLS=0
for tool in waybackurls gau httpx subfinder assetfinder amass; do
    echo -n "    - $tool: "
    if command -v "$tool" >/dev/null 2>&1; then
        echo -e "${GREEN}FOUND${NC}"
    else
        echo -e "${RED}MISSING${NC}"
        MISSING_TOOLS=$((MISSING_TOOLS + 1))
    fi
done

# 2b. Validate httpx is ProjectDiscovery httpx (avoid python httpx CLI)
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

echo -n "[*] Validating httpx flavor (ProjectDiscovery expected)... "
HTTPX_PATH="$(command -v httpx 2>/dev/null || true)"
if [[ -z "$HTTPX_PATH" ]]; then
  echo -e "${YELLOW}SKIP${NC} (httpx not found)"
else
  if is_pd_httpx "$HTTPX_PATH"; then
    echo -e "${GREEN}OK${NC} ($HTTPX_PATH)"
  else
    echo -e "${YELLOW}WARN${NC} ($HTTPX_PATH)"
    echo "    -> This does not look like ProjectDiscovery httpx (possible python httpx CLI)."
    echo "    -> Fix: install PD httpx with: go install github.com/projectdiscovery/httpx/cmd/httpx@latest"
  fi
fi

if [ $MISSING_TOOLS -gt 0 ]; then
    echo -e "${YELLOW}[!] Warning: $MISSING_TOOLS tools are missing. Run 'phase1_install.sh' or install them manually.${NC}"
else
    echo -e "${GREEN}[+] All external tools found.${NC}"
fi

# 3. Check API Keys (Environment Variables)
echo "[*] Checking API Keys (Optional but recommended):"

check_key() {
    local var_name="$1"
    local display_name="$2"
    if [ -n "${!var_name:-}" ]; then
         echo -e "    - $display_name: ${GREEN}SET${NC}"
    else
         echo -e "    - $display_name: ${YELLOW}NOT SET${NC} (Features using this will be skipped)"
    fi
}

check_key "SHODAN_API_KEY" "Shodan"
check_key "CENSYS_API_KEY" "Censys (V3/Platform)"
check_key "SECURITYTRAILS_KEY" "SecurityTrails"
check_key "URLSCAN_API_KEY" "Urlscan.io"
check_key "GITHUB_TOKEN" "GitHub Token"

# 4. Storage Checks
echo "[*] Storage Check:"
FREE_SPACE=$(df -h . | awk 'NR==2 {print $4}')
echo -e "    - Free space in current directory: ${GREEN}$FREE_SPACE${NC}"

echo
echo "=== Pre-Check Complete ==="
if [ $MISSING_TOOLS -eq 0 ]; then
    echo -e "${GREEN}Ready to run Phase 1.${NC}"
else
    echo -e "${YELLOW}System has missing tools, but you can proceed with limited functionality.${NC}"
fi
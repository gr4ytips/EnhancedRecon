#!/usr/bin/env bash
# phase3_precheck.sh
#
# REQUIRED (ReconAggregator artifacts):
#   - gitleaks
#   - osv-scanner
#
# Policy: tools must exist in ~/go/bin

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

VENV_DIR="${VENV_DIR:-$HOME/.venvs/phase3}"
PYTHON="$VENV_DIR/bin/python"
GOBIN_DIR="${GOBIN_DIR:-$HOME/go/bin}"

# Ensure PATH sees ~/go/bin during this run
export PATH="$GOBIN_DIR:$PATH"

echo "=== Phase 3 Environment Pre-Check ==="
echo "GOBIN_DIR=$GOBIN_DIR"
echo

# 1) ExifTool
echo -n "[*] exiftool... "
if command -v exiftool >/dev/null 2>&1; then
  echo -e "${GREEN}FOUND ($(command -v exiftool))${NC}"
else
  echo -e "${RED}MISSING${NC}"
  echo "    -> Run: sudo apt install libimage-exiftool-perl"
fi

# 2) REQUIRED Go tools (must be in ~/go/bin)
echo -n "[*] gitleaks ($GOBIN_DIR/gitleaks)... "
if [ -x "$GOBIN_DIR/gitleaks" ]; then
  echo -e "${GREEN}OK${NC}"
else
  echo -e "${RED}MISSING${NC}"
fi

echo -n "[*] osv-scanner ($GOBIN_DIR/osv-scanner)... "
if [ -x "$GOBIN_DIR/osv-scanner" ]; then
  echo -e "${GREEN}OK${NC}"
else
  echo -e "${RED}MISSING${NC}"
fi

# 3) Python venv
echo -n "[*] venv python ($PYTHON)... "
if [ -x "$PYTHON" ]; then
  echo -e "${GREEN}OK${NC}"
else
  echo -e "${RED}MISSING${NC}"
  exit 1
fi

# 4) Python libs
echo "[*] Python libs:"
LIBS=(pandas openpyxl networkx tldextract colorama magic httpx)
for lib in "${LIBS[@]}"; do
  echo -n "    - $lib: "
  if "$PYTHON" -c "import $lib" >/dev/null 2>&1; then
    echo -e "${GREEN}OK${NC}"
  else
    echo -e "${RED}MISSING${NC}"
  fi
done

# 5) Hard fail if REQUIRED tools missing
missing=0
[ -x "$GOBIN_DIR/gitleaks" ] || missing=1
[ -x "$GOBIN_DIR/osv-scanner" ] || missing=1

if [ "$missing" -ne 0 ]; then
  echo -e "${RED}[X] Phase 3 precheck FAILED: gitleaks/osv-scanner must exist in $GOBIN_DIR${NC}"
  echo "    -> Run: ./phase3_install.sh"
  exit 2
fi

echo
echo "=== Pre-Check Complete ==="
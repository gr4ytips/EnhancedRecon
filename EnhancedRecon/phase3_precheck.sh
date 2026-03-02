#!/usr/bin/env bash
# phase3_precheck.sh

set -u

RED='\033[0;31m'
GREEN='\033[0;32m'
NC='\033[0m'

VENV_DIR="${VENV_DIR:-$HOME/.venvs/phase3}"
PYTHON="$VENV_DIR/bin/python"

echo "=== Phase 3 Environment Pre-Check ==="

# 1. Check ExifTool
echo -n "[*] Checking ExifTool... "
if command -v exiftool >/dev/null 2>&1; then
    echo -e "${GREEN}FOUND ($(command -v exiftool))${NC}"
else
    echo -e "${RED}MISSING${NC}"
    echo "    -> Run: sudo apt install libimage-exiftool-perl"
fi

# 2. Check Python Venv
echo -n "[*] Checking Venv ($VENV_DIR)... "
if [ -x "$PYTHON" ]; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}MISSING${NC}"
    exit 1
fi

# 3. Check Libraries
echo "[*] Checking Python Libraries:"
LIBS="pandas openpyxl networkx tldextract colorama magic httpx"
for lib in $LIBS; do
    echo -n "    - $lib: "
    if "$PYTHON" -c "import $lib" 2>/dev/null; then
        echo -e "${GREEN}OK${NC}"
    else
        echo -e "${RED}MISSING${NC}"
    fi
done

echo "=== Pre-Check Complete ==="
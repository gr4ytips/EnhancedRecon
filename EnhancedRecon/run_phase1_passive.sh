#!/usr/bin/env bash
# run_phase1_passive.sh
# Phase 1: Passive/Archive Recon
# - Builds a scoped domain list (suffix + exact allowlist, minus exclusions)
# - Runs recon_phase1_one_stage.py -> recon_pipeline.py
# - Writes seeds file(s) for Phase 2

set -euo pipefail

# If someone runs `sh script.sh`, re-exec with bash so [[ ... ]] works.
if [[ -z "${BASH_VERSION:-}" ]]; then
  exec /usr/bin/env bash "$0" "$@"
fi

# ----------------------------
# Config (edit if needed)
# ----------------------------
# Resolve ROOT/TOOLS automatically.
# - If the script is in the program root: ROOT=<that folder>
# - If the script is in tools/custom-recon-tools_EXPANDED: ROOT=../..
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -d "$SCRIPT_DIR/tools/custom-recon-tools_EXPANDED" ]]; then
  ROOT="${ROOT:-$SCRIPT_DIR}"
else
  ROOT="${ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
fi
TOOLS="${TOOLS:-$ROOT/tools/custom-recon-tools_EXPANDED}"
PHASE1_OUTROOT="$ROOT/passive_enum_phase1"
PHASE1_ROOT="$PHASE1_OUTROOT/phase1_iter_1"

# Scope files
ALLOWED_DOMAINS_FILE="$ROOT/allowed_domains.txt"            # legacy / reference
ALLOWED_SUFFIXES_FILE="$ROOT/allowed_suffixes.txt"          # eTLD+1 suffix allowlist
ALLOWED_EXACT_FILE="$ROOT/allowed_exact_hosts.txt"          # exact host allowlist
EXCLUDE_HOSTS_FILE="$ROOT/out_of_scope_hosts.txt"           # explicit out-of-scope hosts

# Best inputs (from Phase0/StepBC). We will pick the first non-empty.
INPUT_CANDIDATES=(
  "$ROOT/out/stepBC/subs_nowildcard_resolved.txt"
  "$ROOT/out/stepBC/subs_nowildcard.txt"
  "$ROOT/out/stepBC/subs_unique.txt"
  "$ALLOWED_EXACT_FILE"
)

# IA CDX range (optional tuning)
YFROM="${YFROM:-2025}"
YTO="${YTO:-2026}"

# Tool commands (override via env; default uses PATH)
WAYBACKURLS_BIN="${WAYBACKURLS_BIN:-waybackurls}"
GAU_BIN="${GAU_BIN:-gau}"

mkdir -p "$PHASE1_OUTROOT" "$PHASE1_ROOT"

# ----------------------------
# Python selection (prefer Phase1 venv)
# ----------------------------
VENV_DIR="${VENV_DIR:-$HOME/.venvs/phase1}"
VENV_PY="$VENV_DIR/bin/python"
PY="${VENV_PYTHON:-$VENV_PY}"
if [[ ! -x "$PY" ]]; then
  PY="python3"
  echo "[WARN] Phase1 venv python not found at: $VENV_PY" >&2
  echo "       Falling back to system python3. Recommended: ./phase1_install.sh && ./phase1_precheck.sh" >&2
fi

# ----------------------------
# Safety checks
# ----------------------------
[[ -d "$ROOT" ]] || { echo "❌ ROOT not found: $ROOT" >&2; exit 1; }
[[ -d "$TOOLS" ]] || { echo "❌ TOOLS not found: $TOOLS" >&2; exit 1; }
[[ -f "$TOOLS/recon_phase1_one_stage.py" ]] || { echo "❌ Missing: $TOOLS/recon_phase1_one_stage.py" >&2; exit 1; }
[[ -f "$TOOLS/recon_pipeline.py" ]] || { echo "❌ Missing: $TOOLS/recon_pipeline.py" >&2; exit 1; }
[[ -f "$TOOLS/scope_filter.py" ]] || { echo "❌ Missing: $TOOLS/scope_filter.py" >&2; exit 1; }
[[ -f "$ALLOWED_SUFFIXES_FILE" ]] || { echo "❌ Missing: $ALLOWED_SUFFIXES_FILE" >&2; exit 1; }
[[ -f "$ALLOWED_EXACT_FILE" ]] || { echo "❌ Missing: $ALLOWED_EXACT_FILE" >&2; exit 1; }
command -v "$PY" >/dev/null 2>&1 || { echo "❌ Python not found: $PY" >&2; exit 1; }

# ----------------------------
# resolve ProjectDiscovery httpx (avoid python httpx CLI collision)
# ----------------------------
HTTPX_BIN="${HTTPX_BIN:-}"
HTTPX_ARG=()

is_pd_httpx() {
  local bin="$1"
  [[ -z "$bin" ]] && return 1

  local resolved_bin=""
  if [[ "$bin" == /* ]]; then
    resolved_bin="$bin"
  else
    resolved_bin="$(command -v "$bin" 2>/dev/null || true)"
  fi
  [[ -z "$resolved_bin" ]] && return 1
  [[ ! -x "$resolved_bin" ]] && return 1
# ProjectDiscovery httpx supports -version/--version; python httpx CLI does not.
  "$resolved_bin" -version >/dev/null 2>&1 && return 0
  "$resolved_bin" --version >/dev/null 2>&1 && return 0
# Fallback: help text contains flags used by PD httpx
  local h
  h="$("$resolved_bin" -h 2>&1 || true)"
  echo "$h" | grep -q -- "-silent" || return 1
  echo "$h" | grep -q -- "-l"      || return 1
  return 0
}

# If user exported HTTPX_BIN, validate it.
if [[ -n "$HTTPX_BIN" ]]; then
  if ! is_pd_httpx "$HTTPX_BIN"; then
    echo "[WARN] HTTPX_BIN is set but not ProjectDiscovery httpx; ignoring: $HTTPX_BIN" >&2
    HTTPX_BIN=""
  fi
fi

# Auto-detect ProjectDiscovery httpx if not set.
if [[ -z "$HTTPX_BIN" ]]; then
  for c in \
    "$(command -v httpx 2>/dev/null || true)" \
    "$(command -v httpx-pd 2>/dev/null || true)" \
    "$HOME/go/bin/httpx" \
    "/usr/local/bin/httpx" \
    "/usr/bin/httpx"
  do
    [[ -n "$c" ]] || continue
    if is_pd_httpx "$c"; then
      HTTPX_BIN="$c"
      break
    fi
  done
fi

if [[ -n "$HTTPX_BIN" ]]; then
  HTTPX_ARG=( --httpx "$HTTPX_BIN" )
else
  echo "[WARN] ProjectDiscovery httpx not found; continuing without --httpx." >&2
fi

# ----------------------------
# Pick input source
# ----------------------------
INPUT_SRC=""
for f in "${INPUT_CANDIDATES[@]}"; do
  if [[ -s "$f" ]]; then
    INPUT_SRC="$f"
    break
  fi
done

echo ">>> Phase1 input candidates:"
for f in "${INPUT_CANDIDATES[@]}"; do echo "    - $f"; done

if [[ -z "$INPUT_SRC" ]]; then
  echo "❌ No usable input file found (all empty/missing)." >&2
  exit 1
fi
echo ">>> Input: $INPUT_SRC"

# ----------------------------
# Build scoped input list (single source of truth = scope_filter.py)
# ----------------------------
SCOPED_INPUT="$PHASE1_OUTROOT/_phase1_scoped_input_domains.txt"

"$PY" "$TOOLS/scope_filter.py" \
  --inputs "$INPUT_SRC" \
  --suffixes "$ALLOWED_SUFFIXES_FILE" \
  --exact "$ALLOWED_EXACT_FILE" \
  --exclude "$EXCLUDE_HOSTS_FILE" \
  --out "$SCOPED_INPUT"

HOSTS_COUNT="$(wc -l < "$SCOPED_INPUT" | tr -d ' ')"

echo "======================================================="
echo " PHASE 1 PASSIVE: ENHANCED"
echo " ROOT       : $ROOT"
echo " TOOLS      : $TOOLS"
echo " PY         : $PY"
echo " INPUT(src) : $INPUT_SRC"
echo " INPUT(use) : $SCOPED_INPUT (hosts=$HOSTS_COUNT)"
echo " SUFFIXES   : $ALLOWED_SUFFIXES_FILE"
echo " EXACT      : $ALLOWED_EXACT_FILE"
echo " EXCLUDE    : $EXCLUDE_HOSTS_FILE"
echo " OUT        : $PHASE1_ROOT"
echo " CDX RANGE  : $YFROM .. $YTO"
echo " HTTPX      : ${HTTPX_BIN:-<not found>}"
echo "======================================================="

if [[ "$HOSTS_COUNT" -eq 0 ]]; then
  echo "❌ Scoped input is empty; refusing to run Phase1." >&2
  exit 1
fi

# Optional: precheck if present (tools tree)
if [[ -x "$TOOLS/phase1_precheck.sh" ]]; then
  "$TOOLS/phase1_precheck.sh" || true
fi

echo ">>> Running recon_phase1_one_stage.py"
"$PY" "$TOOLS/recon_phase1_one_stage.py" \
  --input "$SCOPED_INPUT" \
  --outdir "$PHASE1_ROOT" \
  --strict-scope yes \
  --allowed-suffixes-file "$ALLOWED_SUFFIXES_FILE" \
  --allowed-exact-hosts-file "$ALLOWED_EXACT_FILE" \
  --exclude-hosts-file "$EXCLUDE_HOSTS_FILE" \
  --allowed-domains-file "$ALLOWED_SUFFIXES_FILE" \
  --pipeline-cmd "$PY $TOOLS/recon_pipeline.py" \
  --passive-only yes \
  --waybackurls "$WAYBACKURLS_BIN" \
  --gau "$GAU_BIN" \
  "${HTTPX_ARG[@]}" \
  --enable-wayback-cdx yes \
  --cdx-from "$YFROM" \
  --cdx-to "$YTO" \
  --enable-cc no \
  --enable-cc-bodies no \
  --enable-otx yes \
  --enable-urlscan yes \
  --enable-ct yes \
  --enable-shodan yes \
  --fetch-archive-bodies yes \
  --archive-max-per-path 1 \
  --archive-period month \
  --archive-mime-allow "text/html,application/javascript,application/json,text/javascript,application/xml,text/xml,text/plain,text/x-yaml" \
  --enable-phase1-addons yes \
  --enable-registry-osint no \
  --enable-pdns yes \
  --enable-censys yes \
  --enable-github-osint yes \
  --enable-subdomains no \
  --debug
  #--ccb-max-per-path 1 \

# Save outputs for Phase 2:
# - Always save the actual scoped host list used by Phase 1
cp -v "$SCOPED_INPUT" "$PHASE1_OUTROOT/_scope_hosts_current.txt"
# - Keep legacy behavior for _seeds_current.txt if allowed_domains.txt exists
if [[ -f "$ALLOWED_DOMAINS_FILE" ]]; then
  cp -v "$ALLOWED_DOMAINS_FILE" "$PHASE1_OUTROOT/_seeds_current.txt"
else
  cp -v "$SCOPED_INPUT" "$PHASE1_OUTROOT/_seeds_current.txt"
fi

echo "======================================================="
echo "✅ Phase 1 Passive Complete"
echo "   Output : $PHASE1_ROOT"
echo "   Scope  : $PHASE1_OUTROOT/_scope_hosts_current.txt"
echo "   Seeds  : $PHASE1_OUTROOT/_seeds_current.txt"
echo "======================================================="
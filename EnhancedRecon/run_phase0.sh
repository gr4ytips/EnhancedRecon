#!/usr/bin/env bash
# Robustly re-exec with bash even if someone runs: sh run_phase0.sh
if [ -z "${BASH_VERSION:-}" ]; then
  exec bash "$0" "$@"
fi

# Prefer ProjectDiscovery tools installed via `go install`.
export PATH="$HOME/go/bin:$PATH"

set -euo pipefail

# Resolve ROOT/TOOLS automatically to support execution from program root OR tools directory.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -d "$SCRIPT_DIR/tools/custom-recon-tools_EXPANDED" ]]; then
  ROOT="${ROOT:-$SCRIPT_DIR}"
else
  ROOT="${ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
fi
TOOLS="${TOOLS:-$ROOT/tools/custom-recon-tools_EXPANDED}"
OUTDIR="${OUTDIR:-$ROOT/out}"

# --- Python selection (prefer Phase0 venv) ---
VENV_DIR="${VENV_DIR:-$HOME/.venvs/phase0}"
VENV_PY="$VENV_DIR/bin/python"
PY="${VENV_PYTHON:-$VENV_PY}"
if [[ ! -x "$PY" ]]; then
  PY="python3"
  echo "[WARN] Phase0 venv python not found at: $VENV_PY"
  echo "       Falling back to system python3. Recommended: ./phase0_install.sh && ./phase0_precheck.sh" >&2
fi

# --- User-tunable toggles ---
# RUN_AMASS: yes|no  (default: no) — amass often times out and slows runs.
# CHECK_LIVE: yes|no (default: yes) — active HTTP/TCP liveness checks in StepD.
# USE_KNOWN_DOMAINS: yes|no (default: no) — if yes, union orgs/known-domains into Step0 seeds.
# STOP_AFTER: stepa|stepbc|stepd — stop after that stage (useful for manual review).
RUN_AMASS="${RUN_AMASS:-no}"
CHECK_LIVE="${CHECK_LIVE:-yes}"
USE_KNOWN_DOMAINS="${USE_KNOWN_DOMAINS:-no}"
STOP_AFTER="${STOP_AFTER:-}"

# DNS resolvers used by StepA/BC/D (comma-separated).
RESOLVERS="${RESOLVERS:-1.1.1.1,8.8.8.8}"

# normalize yes/no-ish values
_norm_yesno() {
  local v="${1:-}"; v="${v,,}"
  case "$v" in
    1|y|yes|true|on) echo yes ;;
    *)               echo no  ;;
  esac
}
RUN_AMASS="$(_norm_yesno "$RUN_AMASS")"
CHECK_LIVE="$(_norm_yesno "$CHECK_LIVE")"
USE_KNOWN_DOMAINS="$(_norm_yesno "$USE_KNOWN_DOMAINS")"
STOP_AFTER="${STOP_AFTER,,}"

# dnsx detection (will be the ~/go/bin one because PATH is prefixed above)
DNSX_BIN="$(command -v dnsx 2>/dev/null || true)"
DNSX_ARGS=()
if [[ -n "$DNSX_BIN" ]]; then
  DNSX_ARGS+=( --dnsx-path "$DNSX_BIN" )
fi

# --- Inputs ---
ALLOWED_SUFFIXES="$ROOT/allowed_suffixes.txt"
ALLOWED_EXACT="$ROOT/allowed_exact_hosts.txt"
OOS_HOSTS="$ROOT/out_of_scope_hosts.txt"

mkdir -p "$OUTDIR"

# --------- fail-fast checks ----------
[[ -f "$ALLOWED_SUFFIXES" ]] || { echo "[FAIL] Missing: $ALLOWED_SUFFIXES" >&2; exit 1; }
[[ -f "$ALLOWED_EXACT"    ]] || { echo "[FAIL] Missing: $ALLOWED_EXACT" >&2; exit 1; }
[[ -f "$TOOLS/scope_filter.py" ]] || { echo "[FAIL] Missing: $TOOLS/scope_filter.py" >&2; exit 1; }
[[ -f "$TOOLS/expand_ips_to_domains_fcrdns_api_debug.py" ]] || { echo "[FAIL] Missing: $TOOLS/expand_ips_to_domains_fcrdns_api_debug.py" >&2; exit 1; }
[[ -f "$TOOLS/expand_and_enum_subs.py" ]] || { echo "[FAIL] Missing: $TOOLS/expand_and_enum_subs.py" >&2; exit 1; }
[[ -f "$TOOLS/ip_assets_enrich.py" ]] || { echo "[FAIL] Missing: $TOOLS/ip_assets_enrich.py" >&2; exit 1; }
command -v "$PY" >/dev/null 2>&1 || { echo "[FAIL] python not found: $PY" >&2; exit 1; }
# -------------------------------------

# helper: stop-point
_stop_if() {
  local key="$1"
  if [[ -n "$STOP_AFTER" ]] && [[ "$STOP_AFTER" == "$key" ]]; then
    echo "[*] STOP_AFTER=$STOP_AFTER -> stopping after $key"
    exit 0
  fi
}

echo "======================================================="
echo " PHASE 0"
echo " ROOT      : $ROOT"
echo " TOOLS     : $TOOLS"
echo " OUTDIR    : $OUTDIR"
echo " PY        : $PY"
echo " RESOLVERS : $RESOLVERS"
echo " RUN_AMASS : $RUN_AMASS"
echo " CHECK_LIVE: $CHECK_LIVE"
echo " USE_KNOWN_DOMAINS: $USE_KNOWN_DOMAINS"
echo " STOP_AFTER: ${STOP_AFTER:-<none>}"
echo "======================================================="

# ---------------------------
# Step0: build seeds_for_A.txt
# ---------------------------
echo "[*] Step0: build seeds_for_A.txt"
mkdir -p "$OUTDIR/step0" "$OUTDIR/stepA" "$OUTDIR/stepBC" "$OUTDIR/stepD"
SEEDS_FOR_A="$OUTDIR/step0/seeds_for_A.txt"

# Build enumeration seeds from suffix allowlist (and optionally org/known-domains).
# NOTE: Exact hosts are NOT used as enumeration seeds (but they will still be forced in-scope in StepA.5 / StepC.5).
{
  cat "$ALLOWED_SUFFIXES" 2>/dev/null || true
  if [[ "$USE_KNOWN_DOMAINS" == "yes" ]]; then
    cat "$ROOT/orgs.txt" "$ROOT/known_domains.txt" 2>/dev/null || true
  else
    echo "[i] USE_KNOWN_DOMAINS=no (using scope allowlists only)" >&2
  fi
} \
| awk '{print tolower($0)}' \
| sed -E 's#^https?://##; s#/.*$##; s#:[0-9]+$##; s#\s+$##; s#^\*\.(.+)$#\1#; s#^\.(.+)$#\1#' \
| grep -E '^[a-z0-9.-]+\.[a-z]{2,}$' \
| awk 'NF' \
| sort -u \
> "$SEEDS_FOR_A"

SEED_COUNT="$(wc -l < "$SEEDS_FOR_A" | tr -d ' ')"
echo "[*] seeds_for_A count: $SEED_COUNT"
if [[ "$SEED_COUNT" -eq 0 ]]; then
  echo "[FAIL] seeds_for_A is empty; check $ALLOWED_SUFFIXES / known_domains.txt" >&2
  exit 1
fi

# ---------------------------
# StepA: expand_ips_to_domains_fcrdns_api_debug
# ---------------------------
echo "[*] StepA: expand_ips_to_domains_fcrdns_api_debug"
mkdir -p "$OUTDIR/stepA"

ENUM_TOOLS="assetfinder,subfinder"
if [[ "$RUN_AMASS" == "yes" ]]; then
  ENUM_TOOLS="$ENUM_TOOLS,amass"
fi

"$PY" "$TOOLS/expand_ips_to_domains_fcrdns_api_debug.py" \
  --in "$SEEDS_FOR_A" \
  --out "$OUTDIR/stepA/hosts.txt" \
  --emit-map "$OUTDIR/stepA/ip_to_host_map.csv" \
  --resolvers "$RESOLVERS" \
  --verify-fcrdns yes \
  --enum-domains yes \
  --enum-tools "$ENUM_TOOLS" \
  --enum-wrapper-timeout 1800 \
  --workers 32 \
  --timeout 8 \
  --log-level "${RECON_LOG_LEVEL:-DEBUG}" \
  --stats-json "$OUTDIR/stepA/seeds_expanded_run_stats.json"

# ---------------------------
# StepA.5: scope-filter StepA hosts (suffix + exact, minus explicit exclusions)
#   - also FORCE-INCLUDE exact hosts (even if StepA didn’t discover them)
# ---------------------------
echo "[*] StepA.5: scope-filter StepA hosts (suffix + exact, minus explicit exclusions)"
"$PY" "$TOOLS/scope_filter.py" \
  --inputs "$OUTDIR/stepA/hosts.txt" \
  --suffixes "$ALLOWED_SUFFIXES" \
  --exact "$ALLOWED_EXACT" \
  --exclude "$OOS_HOSTS" \
  --out "$OUTDIR/stepA/hosts_scoped.txt"

_stop_if stepa

# ---------------------------
# StepBC: expand_and_enum_subs
# ---------------------------
echo "[*] StepBC: expand_and_enum_subs"
mkdir -p "$OUTDIR/stepBC"
# Build comma-separated restrict suffix list from the allowlist (strip wildcards/dots).
RESTRICT_SUFFIX_CSV="$(
  grep -vE '^\s*(#|$)' "$ALLOWED_SUFFIXES" 2>/dev/null \
  | awk '{print tolower($0)}' \
  | sed -E 's#^\*\.(.+)$#\1#; s#^\.(.+)$#\1#' \
  | awk 'NF' \
  | tr '\n' ',' | sed 's/,$//'
)"
if [[ -z "$RESTRICT_SUFFIX_CSV" ]]; then
  echo "[FAIL] allowed_suffixes.txt produced empty restrict list; refusing to run StepBC." >&2
  exit 1
fi

DBG_FLAG="no"; [[ "${RECON_LOG_LEVEL:-INFO}" == "DEBUG" ]] && DBG_FLAG="yes"

"$PY" "$TOOLS/expand_and_enum_subs.py" \
  --in "$OUTDIR/stepA/hosts_scoped.txt" \
  --out-dir "$OUTDIR/stepBC" \
  --workers 32 \
  --timeout 8 \
  --resolvers "$RESOLVERS" \
  --verify-fcrdns yes \
  --shodan auto \
  --securitytrails auto \
  --censys auto \
  --ipinfo auto \
  --enumerate yes \
  --restrict-suffix "$RESTRICT_SUFFIX_CSV" \
  --include-apex no \
  --resolve yes \
  "${DNSX_ARGS[@]}" \
  --dnsx-rate 400 \
  --dnsx-retries 2 \
  --dnsx-timeout 8 \
  --wildcard-filter yes \
  --wildcard-samples 15 \
  --wildcard-max-ips 8 \
  --debug "$DBG_FLAG" \
  --emit-map "$OUTDIR/stepBC/expand_and_enum_subs_map.csv"

# ---------------------------
# StepC.5: apply scope filters for active probing
#   - also FORCE-INCLUDE exact hosts
# ---------------------------
echo "[*] StepC.5: apply scope filters (suffix + exact, minus explicit exclusions) for active probing"
"$PY" "$TOOLS/scope_filter.py" \
  --inputs "$OUTDIR/stepBC/subs_nowildcard.txt" \
  --suffixes "$ALLOWED_SUFFIXES" \
  --exact "$ALLOWED_EXACT" \
  --exclude "$OOS_HOSTS" \
  --out "$OUTDIR/stepBC/hosts_scoped_for_stepD.txt"

_stop_if stepbc

# ---------------------------
# StepD: ip_assets_enrich
# ---------------------------
echo "[*] StepD: ip_assets_enrich"
mkdir -p "$OUTDIR/stepD"

"$PY" "$TOOLS/ip_assets_enrich.py" \
  --domains-file "$OUTDIR/stepBC/hosts_scoped_for_stepD.txt" \
  --output "$OUTDIR/stepD/ip_assets.csv" \
  --dnsx yes \
  "${DNSX_ARGS[@]}" \
  --resolvers "$RESOLVERS" \
  --check-live "$CHECK_LIVE" \
  --dnsx-hard-timeout 900 \
  --log "${RECON_LOG_LEVEL:-INFO}"

_stop_if stepd

echo "[*] Done core steps (0/A/BC/D). Next: Phase1 as per runbook."
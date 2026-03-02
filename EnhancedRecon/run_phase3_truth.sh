#!/usr/bin/env bash
set -euo pipefail

# Phase 3 truth-layer runner (safe HTTP validation) — EXACT scope only.
# Usage:
#   ./run_phase3_truth.sh <phase2_output_root> <allowed_exact_hosts_file>
#
# Env overrides:
#   PYTHON=python3
#   SCRIPT=/path/to/phase3_truth_http.py
#   CONCURRENCY=8
#   TIMEOUT=10
#   MAX_URLS=0
#   DOMAIN_FILTER=""
#   RESUME=yes|no   (default: yes)

PHASE2_OUTPUT_ROOT="${1:-}"
SCOPE_FILE="${2:-}"

if [[ -z "$PHASE2_OUTPUT_ROOT" || -z "$SCOPE_FILE" ]]; then
  echo "Usage: $0 <phase2_output_root> <allowed_exact_hosts_file>"
  exit 2
fi

TOOLS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Prefer Phase3 venv python if present (fresh Kali safe)
DEFAULT_VENV_PY="$HOME/.venvs/phase3/bin/python"
if [[ -x "$DEFAULT_VENV_PY" ]]; then
  PY="${PYTHON:-$DEFAULT_VENV_PY}"
else
  PY="${PYTHON:-python3}"
fi

# Defaults
CONCURRENCY="${CONCURRENCY:-8}"
TIMEOUT="${TIMEOUT:-10}"
MAX_URLS="${MAX_URLS:-0}"
DOMAIN_FILTER="${DOMAIN_FILTER:-}"
RESUME="${RESUME:-yes}"

_norm_yesno() {
  local v="${1:-}"; v="${v,,}"
  case "$v" in
    1|y|yes|true|on) echo yes ;;
    *)               echo no  ;;
  esac
}
RESUME="$(_norm_yesno "$RESUME")"

# Default: truth script lives inside tools/custom-recon-tools_EXPANDED
SCRIPT="${SCRIPT:-${TOOLS_DIR}/tools/custom-recon-tools_EXPANDED/phase3_truth_http.py}"

[[ -d "$PHASE2_OUTPUT_ROOT" ]] || { echo "Root not found: $PHASE2_OUTPUT_ROOT" >&2; exit 2; }
[[ -f "$SCOPE_FILE" ]] || { echo "Scope file not found: $SCOPE_FILE" >&2; exit 2; }
[[ -f "$SCRIPT" ]] || { echo "Missing: $SCRIPT" >&2; exit 2; }

ARGS=( --root "$PHASE2_OUTPUT_ROOT" --allowed "$SCOPE_FILE" --concurrency "$CONCURRENCY" --timeout "$TIMEOUT" --max-urls "$MAX_URLS" )
[[ -n "$DOMAIN_FILTER" ]] && ARGS+=( --domain-filter "$DOMAIN_FILTER" )
[[ "$RESUME" == "yes" ]] && ARGS+=( --resume )

echo "======================================================="
echo " PHASE 3 TRUTH (safe HTTP validation)"
echo " ROOT        : $PHASE2_OUTPUT_ROOT"
echo " ALLOWED     : $SCOPE_FILE"
echo " PYTHON      : $PY"
echo " SCRIPT      : $SCRIPT"
echo " CONCURRENCY : $CONCURRENCY"
echo " TIMEOUT     : $TIMEOUT"
echo " MAX_URLS    : $MAX_URLS"
echo " DOMAIN_FILT : ${DOMAIN_FILTER:-<none>}"
echo " RESUME      : $RESUME"
echo "======================================================="

"$PY" "$SCRIPT" "${ARGS[@]}"
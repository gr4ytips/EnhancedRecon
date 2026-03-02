#!/usr/bin/env bash
set -euo pipefail

# Phase 3 truth-layer runner (safe HTTP validation) — EXACT scope only.
# Usage (legacy positional):
#   ./run_phase3_truth.sh <phase2_output_root> <allowed_exact_hosts_file>
#
# Usage (flags):
#   ./run_phase3_truth.sh --phase2-root <dir> --scope-hosts <file> [--domain-filter <regex>]
#
# Env overrides:
#   PYTHON=python3
#   SCRIPT=/path/to/phase3_truth_http.py
#   CONCURRENCY=8
#   TIMEOUT=10
#   MAX_URLS=0
#   DOMAIN_FILTER=""
#   RESUME=yes|no   (default: yes)

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

usage() {
  cat <<EOF
Usage:
  $0 <phase2_output_root> <allowed_exact_hosts_file>

  $0 --phase2-root <dir> --scope-hosts <file> [options]

Options:
  --phase2-root <dir>        Phase-2 output root (e.g., passive_enum_phase1/phase1_iter_1_phase2)
  --scope-hosts <file>       Allowed exact hosts file
  --domain-filter <regex>    Optional domain filter
  --concurrency <n>          Override CONCURRENCY
  --timeout <seconds>        Override TIMEOUT
  --max-urls <n>             Override MAX_URLS (0 = unlimited)
  --resume / --no-resume     Override RESUME
  -h, --help                 Show help
EOF
}

PHASE2_OUTPUT_ROOT=""
SCOPE_FILE=""

# Parse args:
# - If first arg is not a flag -> positional mode
# - Else flag mode
if [[ $# -ge 1 && "${1:-}" != --* ]]; then
  PHASE2_OUTPUT_ROOT="${1:-}"
  SCOPE_FILE="${2:-}"
else
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --phase2-root|--root)
        PHASE2_OUTPUT_ROOT="${2:-}"; shift 2;;
      --scope-hosts|--allowed|--allowed-hosts)
        SCOPE_FILE="${2:-}"; shift 2;;
      --domain-filter)
        DOMAIN_FILTER="${2:-}"; shift 2;;
      --concurrency)
        CONCURRENCY="${2:-}"; shift 2;;
      --timeout)
        TIMEOUT="${2:-}"; shift 2;;
      --max-urls)
        MAX_URLS="${2:-}"; shift 2;;
      --resume)
        RESUME="yes"; shift 1;;
      --no-resume)
        RESUME="no"; shift 1;;
      -h|--help)
        usage; exit 0;;
      *)
        echo "Unknown arg: $1" >&2
        usage
        exit 2;;
    esac
  done
fi

if [[ -z "$PHASE2_OUTPUT_ROOT" || -z "$SCOPE_FILE" ]]; then
  usage
  exit 2
fi

[[ -d "$PHASE2_OUTPUT_ROOT" ]] || { echo "Root not found: $PHASE2_OUTPUT_ROOT" >&2; exit 2; }
[[ -f "$SCOPE_FILE" ]] || { echo "Scope file not found: $SCOPE_FILE" >&2; exit 2; }
[[ -f "$SCRIPT" ]] || { echo "Missing: $SCRIPT" >&2; exit 2; }

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

# Call python script in a compatible way:
# - Prefer flags (--root/--allowed) if supported
# - Else fall back to positional: <root> <allowed>
HELP_OUT="$("$PY" "$SCRIPT" -h 2>&1 || true)"

if echo "$HELP_OUT" | grep -q -- '--root' && echo "$HELP_OUT" | grep -q -- '--allowed'; then
  ARGS=( --root "$PHASE2_OUTPUT_ROOT" --allowed "$SCOPE_FILE" )
  if echo "$HELP_OUT" | grep -q -- '--concurrency'; then ARGS+=( --concurrency "$CONCURRENCY" ); fi
  if echo "$HELP_OUT" | grep -q -- '--timeout'; then ARGS+=( --timeout "$TIMEOUT" ); fi
  if echo "$HELP_OUT" | grep -q -- '--max-urls'; then ARGS+=( --max-urls "$MAX_URLS" ); fi
  [[ -n "$DOMAIN_FILTER" ]] && ARGS+=( --domain-filter "$DOMAIN_FILTER" )
  [[ "$RESUME" == "yes" ]] && ARGS+=( --resume )
  exec "$PY" "$SCRIPT" "${ARGS[@]}"
else
  # Positional python CLI: <root> <allowed> [optional flags if supported]
  ARGS=( "$PHASE2_OUTPUT_ROOT" "$SCOPE_FILE" )
  if echo "$HELP_OUT" | grep -q -- '--concurrency'; then ARGS+=( --concurrency "$CONCURRENCY" ); fi
  if echo "$HELP_OUT" | grep -q -- '--timeout'; then ARGS+=( --timeout "$TIMEOUT" ); fi
  if echo "$HELP_OUT" | grep -q -- '--max-urls'; then ARGS+=( --max-urls "$MAX_URLS" ); fi
  [[ -n "$DOMAIN_FILTER" ]] && ARGS+=( --domain-filter "$DOMAIN_FILTER" )
  [[ "$RESUME" == "yes" ]] && ARGS+=( --resume )
  exec "$PY" "$SCRIPT" "${ARGS[@]}"
fi
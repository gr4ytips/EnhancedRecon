#!/usr/bin/env bash
# run_phase3.sh
# Phase 3: Offline Intelligence & Forensics
# - endpoint clusters, param hotspots, then-vs-now, findings packs, offline secrets/deps
# - metadata forensics (authors, embedded urls, mime mismatches)

set -euo pipefail

# If someone runs `sh script.sh`, re-exec with bash so [[ ... ]] works.
if [[ -z "${BASH_VERSION:-}" ]]; then
  exec /usr/bin/env bash "$0" "$@"
fi

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
PHASE2_OUTPUT_ROOT="${PHASE2_OUTPUT_ROOT:-$ROOT/passive_enum_phase1/phase1_iter_1_phase2}"

# Go tools policy: ALWAYS use ~/go/bin
GOBIN_DIR="${GOBIN_DIR:-$HOME/go/bin}"
export PATH="$GOBIN_DIR:$PATH"
export GOBIN_DIR

# Prefer EXACT host allowlist (Phase0/Phase1 model). Then prefer Phase1 scoped list. Then fallback to seeds.
ALLOWED_FILE="${ALLOWED_FILE:-$ROOT/allowed_exact_hosts.txt}"
if [[ ! -f "$ALLOWED_FILE" ]]; then
  ALLOWED_FILE="$ROOT/passive_enum_phase1/_scope_hosts_current.txt"
fi
if [[ ! -f "$ALLOWED_FILE" ]]; then
  ALLOWED_FILE="$ROOT/passive_enum_phase1/_seeds_current.txt"
fi

VENV_PYTHON="${VENV_PYTHON:-$HOME/.venvs/phase3/bin/python}"

echo "======================================================="
echo " PHASE 3: OFFLINE INTELLIGENCE"
echo " ROOT      : $ROOT"
echo " TOOLS     : $TOOLS"
echo " INPUT     : $PHASE2_OUTPUT_ROOT"
echo " ALLOWED   : $ALLOWED_FILE"
echo " GOBIN_DIR : $GOBIN_DIR"
echo "======================================================="

[[ -d "$PHASE2_OUTPUT_ROOT" ]] || { echo "❌ Phase2 output not found: $PHASE2_OUTPUT_ROOT" >&2; exit 1; }
[[ -x "$VENV_PYTHON" ]] || { echo "❌ Phase3 venv python not found: $VENV_PYTHON (run phase3_install.sh)" >&2; exit 1; }
[[ -f "$TOOLS/phase3_offline.EXACTSCOPE.py" ]] || { echo "❌ Missing: $TOOLS/phase3_offline.EXACTSCOPE.py" >&2; exit 1; }
[[ -f "$TOOLS/meta_offline_enrich_enhanced.EXACTSCOPE.py" ]] || { echo "❌ Missing: $TOOLS/meta_offline_enrich_enhanced.EXACTSCOPE.py" >&2; exit 1; }
[[ -f "$ALLOWED_FILE" ]] || { echo "❌ Allowed file not found: $ALLOWED_FILE" >&2; exit 1; }

# REQUIRED for ReconAggregator ingestion: gitleaks + osv-scanner
[[ -x "$GOBIN_DIR/gitleaks" ]] || { echo "❌ Missing required: $GOBIN_DIR/gitleaks (run phase3_install.sh)" >&2; exit 1; }
[[ -x "$GOBIN_DIR/osv-scanner" ]] || { echo "❌ Missing required: $GOBIN_DIR/osv-scanner (run phase3_install.sh)" >&2; exit 1; }

# Run Phase3 precheck if available (no sudo, safe)
if [[ -f "$ROOT/phase3_precheck.sh" ]]; then
  bash "$ROOT/phase3_precheck.sh" >/dev/null
fi

# Step 1: Offline intelligence
echo ">>> [Step 1/2] Clusters / Params / Then-vs-Now / Findings / Offline Secrets+Deps"
"$VENV_PYTHON" "$TOOLS/phase3_offline.EXACTSCOPE.py" \
  --root "$PHASE2_OUTPUT_ROOT" \
  --allowed "$ALLOWED_FILE" \
  --min-cluster 3

# Step 2: Metadata forensics
echo ">>> [Step 2/2] Metadata Forensics (Authors / Embedded URLs / MIME mismatches)"
"$VENV_PYTHON" "$TOOLS/meta_offline_enrich_enhanced.EXACTSCOPE.py" \
  --root "$PHASE2_OUTPUT_ROOT" \
  --allowed "$ALLOWED_FILE" \
  --harvest-subdir "harvest"

echo "======================================================="
echo "✅ Phase 3 Complete ... "
echo "   Inspect per-domain outputs under:"
echo "     $PHASE2_OUTPUT_ROOT/<domain>/analysis/offline/"
echo "     $PHASE2_OUTPUT_ROOT/<domain>/analysis/meta/"
echo "   ReconAggregator: run Backfill (Phase-2) to ingest Phase-3 reports."
echo "======================================================="
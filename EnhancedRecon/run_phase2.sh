#!/usr/bin/env bash
# run_phase2.sh
# Phase 2  - NONPROD-capable runner
#
# Adds:
#   --scope-hosts <file>     Use this host allowlist instead of auto-building from Phase1
#   --nonprod-only yes|no    Filter the scope hosts to nonprod markers before running (default: no)
#
set -euo pipefail

if [[ -z "${BASH_VERSION:-}" ]]; then
  exec /usr/bin/env bash "$0" "$@"
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [[ -d "$SCRIPT_DIR/tools/custom-recon-tools_EXPANDED" ]]; then
  ROOT="${ROOT:-$SCRIPT_DIR}"
else
  ROOT="${ROOT:-$(cd "$SCRIPT_DIR/../.." && pwd)}"
fi
TOOLS="${TOOLS:-$ROOT/tools/custom-recon-tools_EXPANDED}"

PHASE1_ROOT_DEFAULT="$ROOT/passive_enum_phase1/phase1_iter_1"
PHASE1_ROOT="${PHASE1_ROOT:-$PHASE1_ROOT_DEFAULT}"
PHASE2_ROOT_DEFAULT="$ROOT/passive_enum_phase1/phase1_iter_1_phase2"
PHASE2_ROOT="${PHASE2_ROOT:-$PHASE2_ROOT_DEFAULT}"

LOG_DIR="$ROOT/recon_logs"
mkdir -p "$PHASE2_ROOT" "$LOG_DIR"

# Scope files
ALLOWED_SUFFIXES="$ROOT/allowed_suffixes.txt"
ALLOWED_EXACT="$ROOT/allowed_exact_hosts.txt"
EXCLUDE_HOSTS="$ROOT/out_of_scope_hosts.txt"
OUT_OF_SCOPE_URL_RULES="$ROOT/out_of_scope_url_rules.json"

# Best host scope source (exact hosts) from Step BC
STEP_BC_HOSTS="$ROOT/out/stepBC/subs_nowildcard_resolved.txt"

# Prefer Phase1 produced scope list, fallback to legacy seeds
ALLOWED_HOSTS_FALLBACK="$ROOT/passive_enum_phase1/_scope_hosts_current.txt"
[[ -f "$ALLOWED_HOSTS_FALLBACK" ]] || ALLOWED_HOSTS_FALLBACK="$ROOT/passive_enum_phase1/_seeds_current.txt"

# Venv tools
VENV_DIR="${VENV_DIR:-$HOME/.venvs/phase2}"
PY="$VENV_DIR/bin/python"
SEMGREP="$VENV_DIR/bin/semgrep"

# Runner options
SCOPE_HOSTS_ARG=""
NONPROD_ONLY="no"

usage() {
  cat <<EOF
Usage: bash run_phase2.sh [--scope-hosts FILE] [--nonprod-only yes|no] [--phase1-root DIR] [--phase2-root DIR]

Examples:
  # Run Phase2 only on non-prod hosts (auto-build host list from Phase1):
  bash run_phase2.sh --nonprod-only yes

  # Run Phase2 with an explicit host allowlist:
  bash run_phase2.sh --scope-hosts /path/nonprod_hosts.txt

EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --scope-hosts) SCOPE_HOSTS_ARG="$2"; shift 2 ;;
    --nonprod-only) NONPROD_ONLY="${2:-no}"; shift 2 ;;
    --phase1-root) PHASE1_ROOT="$2"; shift 2 ;;
    --phase2-root) PHASE2_ROOT="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "Unknown arg: $1" >&2; usage; exit 2 ;;
  esac
done

# --- resolve ProjectDiscovery httpx (avoid python httpx CLI collision) ---
HTTPX_BIN="${HTTPX_BIN:-}"
HTTPX_ARG=()

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
    "/usr/bin/httpx" \
    "/usr/local/bin/httpx-pd"
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
fi

# Precheck (auto-installs missing semgrep/gf/patterns/rules)
PRECHECK="$SCRIPT_DIR/phase2_precheck.sh"
[[ -f "$PRECHECK" ]] || PRECHECK="$ROOT/phase2_precheck.sh"
if [[ -f "$PRECHECK" ]]; then
  bash "$PRECHECK"
fi

# Safety checks
[[ -d "$PHASE1_ROOT" ]] || { echo "[FAIL] PHASE1_ROOT not found: $PHASE1_ROOT" >&2; exit 1; }
[[ -x "$PY" ]] || { echo "[FAIL] Phase2 venv python not found: $PY (run phase2_install.sh)" >&2; exit 1; }
[[ -f "$TOOLS/harvest_and_scan.py" ]] || { echo "[FAIL] Missing: $TOOLS/harvest_and_scan.py" >&2; exit 1; }
[[ -f "$TOOLS/phase2_addons.py" ]] || { echo "[FAIL] Missing: $TOOLS/phase2_addons.py" >&2; exit 1; }
[[ -f "$TOOLS/unpack_sourcemaps.py" ]] || { echo "[FAIL] Missing: $TOOLS/unpack_sourcemaps.py" >&2; exit 1; }
[[ -f "$TOOLS/scope_filter.py" ]] || { echo "[FAIL] Missing: $TOOLS/scope_filter.py" >&2; exit 1; }
[[ -f "$ALLOWED_SUFFIXES" ]] || { echo "[FAIL] Missing: $ALLOWED_SUFFIXES" >&2; exit 1; }
[[ -f "$ALLOWED_EXACT" ]] || { echo "[FAIL] Missing: $ALLOWED_EXACT" >&2; exit 1; }

# 0) Build suffix-based domain regex (for selecting Phase1 folders)
DF_REGEX="$(
  awk 'NF && $1 !~ /^#/{gsub(/\r$/,""); print tolower($1)}' "$ALLOWED_SUFFIXES" \
  | sed -E 's/[][^$.|?*+(){}\\]/\\&/g' \
  | paste -sd'|' -
)"
DF_REGEX="(^|\\.)(((${DF_REGEX})))$"

# 1) Build (or accept) scope hosts file
SCOPE_HOSTS="$PHASE2_ROOT/_phase2_scope_hosts.txt"

if [[ -n "$SCOPE_HOSTS_ARG" ]]; then
  cp -f "$SCOPE_HOSTS_ARG" "$SCOPE_HOSTS"
else
  HOST_FILES_LIST="$PHASE2_ROOT/_phase2_hostfiles.list"
  : > "$HOST_FILES_LIST"
  [[ -f "$STEP_BC_HOSTS" ]] && echo "$STEP_BC_HOSTS" >> "$HOST_FILES_LIST"
  [[ -f "$ALLOWED_HOSTS_FALLBACK" ]] && echo "$ALLOWED_HOSTS_FALLBACK" >> "$HOST_FILES_LIST"

  find "$PHASE1_ROOT" -type f \( \
    -name "ct_domains.txt" -o -name "ct_alt_names.txt" -o \
    -name "pdns_hostnames.txt" -o -name "shodan_hostnames.txt" -o \
    -name "chaos_subdomains.txt" -o -name "circl_pdns.txt" -o \
    -name "asn_domains.txt" -o -name "pdns_fdns.txt" -o -name "pdns_rdns.txt" \
  \) -print 2>/dev/null >> "$HOST_FILES_LIST" || true

  # Unified Scope Filter integration
  "$PY" "$TOOLS/scope_filter.py" \
    --input-list "$HOST_FILES_LIST" \
    --phase1-dir "$PHASE1_ROOT" \
    --suffixes "$ALLOWED_SUFFIXES" \
    --exact "$ALLOWED_EXACT" \
    --exclude "$EXCLUDE_HOSTS" \
    --out "$SCOPE_HOSTS"
fi

# 1b) Non-prod filter (optional)
if [[ "$NONPROD_ONLY" == "yes" ]]; then
  NONPROD_FILE="$PHASE2_ROOT/_nonprod_hosts.txt"
  "$PY" - "$SCOPE_HOSTS" <<'PY' > "$NONPROD_FILE"
import re, sys
from pathlib import Path
hosts=[]
for ln in Path(sys.argv[1]).read_text("utf-8", errors="ignore").splitlines():
    h=ln.strip().lower().strip(".")
    if not h or h.startswith("#") or "." not in h:
        continue
    hosts.append(h)
NONPROD_RE = re.compile(
    r"(?i)(^|[.-])("
    r"dev|test|qa|uat|stg|stage|staging|sandbox|preprod|perf|ppe|int|integration|demo|lab|pilot|sit|"
    r"cqa|cua|xqa\d*|xq\d*|xdev\d*|xstg\d*"
    r")([.-]|$)"
)
out=sorted({h for h in hosts if NONPROD_RE.search(h)})
for h in out:
    print(h)
PY
  NEWCOUNT="$(wc -l < "$NONPROD_FILE" | tr -d " ")"
  echo "[+] nonprod_hosts: $NEWCOUNT -> $NONPROD_FILE"
  if [[ "$NEWCOUNT" -eq 0 ]]; then
    echo "[FAIL] nonprod-only selected 0 hosts; refusing to proceed." >&2
    echo "   Hint: pass a pre-filtered list (nonprod_hosts.txt) and omit --nonprod-only." >&2
    exit 1
  fi
  SCOPE_HOSTS="$NONPROD_FILE"
fi

SCOPE_COUNT="$(wc -l < "$SCOPE_HOSTS" | tr -d ' ')"

# Optional path-level
URL_RULES_ARG=()
if [[ -f "$OUT_OF_SCOPE_URL_RULES" ]]; then
  URL_RULES_ARG=( --exclude-url-rules-json "$OUT_OF_SCOPE_URL_RULES" )
fi

echo "========================================================="
echo " PHASE 2"
echo " ROOT        : $ROOT"
echo " TOOLS       : $TOOLS"
echo " PHASE1_ROOT : $PHASE1_ROOT"
echo " PHASE2_ROOT : $PHASE2_ROOT"
echo " SCOPE_HOSTS : $SCOPE_HOSTS (hosts=$SCOPE_COUNT) NONPROD_ONLY=$NONPROD_ONLY"
echo " DOMAIN_REGEX: $DF_REGEX"
echo " HTTPX       : ${HTTPX_BIN:-<not found>}"
echo "========================================================="

if [[ "$SCOPE_COUNT" -eq 0 ]]; then
  echo "[FAIL] SCOPE_HOSTS is empty; refusing to run Phase2." >&2
  exit 1
fi

# GF patterns
GF_ALL="xss,sqli,ssrf,lfi,rce,redirect,idor,secret-urls,secret-ext,aws-keys,github"

# Harvest & Scan
TS="$(date +%F_%H%M%S)"
LOG_FILE="$LOG_DIR/phase2_${TS}.log"

export PYTHONUNBUFFERED=1
export RECON_LOG_LEVEL="${RECON_LOG_LEVEL:-INFO}"

echo ">>> [Step 1/4] Harvest & Scan (log: $LOG_FILE)"
stdbuf -oL -eL "$PY" -u "$TOOLS/harvest_and_scan.py" \
  --auto-discover "$PHASE1_ROOT" \
  --interactive auto \
  --noninteractive-policy canonical \
  --domain-filter "$DF_REGEX" \
  --include-globs "*.urls,*.links,wayback_clean.txt,wayback_deep.txt,cc_urls.txt,feed_urls.txt,ia_cdx_urls.txt,otx_urls.txt,urlscan_urls.txt,wayback_multiarch.txt,cc_routes.txt,urlhaus_urls.txt,containers_urls.txt,multiaddons_union.txt" \
  --include-host-globs "ct_domains.txt,ct_alt_names.txt,pdns_hostnames.txt,shodan_hostnames.txt,chaos_subdomains.txt,circl_pdns.txt,asn_domains.txt,pdns_fdns.txt,pdns_rdns.txt" \
  --seed-default-paths "/robots.txt,/sitemap.xml,/favicon.ico,/.well-known/security.txt,/.well-known/assetlinks.json,/index.html,/package.json,/package-lock.json,/yarn.lock,/pnpm-lock.yaml,/npm-shrinkwrap.json,/composer.json,/composer.lock,/requirements.txt,/Pipfile.lock,/poetry.lock,/pom.xml,/build.gradle,/go.mod,/Gemfile.lock" \
  --scope "$SCOPE_HOSTS" \
  "${URL_RULES_ARG[@]}" \
  --output "$PHASE2_ROOT" \
  --concurrency 10 \
  --rps 20 \
  --respect-robots "no" \
  --max-size $((50*1024*1024)) \
  --timeout 60 \
  --retries 1 \
  --retry-backoff-cap 30 \
  --respect-retry-after "yes" \
  --retry-after-cap 600 \
  --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36" \
  --write-headers "no" \
  --extra-exts ".hbs,.ejs,.svelte,.njk,.pug,.rss,.atom,.wsdl,.xsd,.toml,.yml,.yaml,.properties,.conf,.config,.wasm,.lock,.zip,.bak,.pdf,.doc,.docx,.xls,.xlsx,.ppt,.pptx,.jpg,.png,.tiff,.webp,.svg,.odt" \
  --enable-sourcemaps "yes" \
  --map-extract-sources "yes" \
  --map-chase-sources "yes" \
  --map-retries 2 \
  --map-timeout 30 \
  --map-head-timeout 8 \
  --gf-patterns "${GF_DIR:-$HOME/.gf}" \
  --gf-include "$GF_ALL" \
  --custom-patterns "" \
  --gf-timeout 360 \
  --ignore-file "" \
  --uca-exts ".html,.xhtml,.js,.mjs,.ts,.tsx,.jsx,.vue,.svelte,.php,.asp,.aspx,.jsp,.jspx,.json,.json5,.xml,.svg,.css,.scss,.less,.webmanifest,.hbs,.ejs,.njk,.pug,.toml,.yml,.yaml,.properties,.conf,.config,.lock" \
  --include-maps-in-uca "yes" \
  --uca-link-mode "copy" \
  --uca-format "html" \
  --uca-enable-semgrep "yes" \
  --uca-enable-debug-log "no" \
  --uca-scan-all-text "yes" \
  --venv "$VENV_DIR" --venv-create \
  --venv-ensure-packages "ijson,semgrep,PyYAML" \
  --uca-reqs "" \
  --uca-wheels "" \
  --uca-auto-install-missing "yes" \
  --pip-extra-index-url "" \
  --post-harvest-js-tools "yes" \
  --js-scan-only-alive "yes" \
  --js-scan-include-local "yes" \
  "${HTTPX_ARG[@]}" \
  --post-max-js-size $((50*1024*1024)) \
  --unfurl "$(command -v unfurl || true)" \
  --linkfinder "$(command -v linkfinder || true)" \
  --secretfinder "$(command -v SecretFinder || true)" \
  --enable-offline-analyzers yes \
  --retirejs "$(command -v retire || true)" \
  --trufflehog "$(command -v trufflehog || true)" \
  --wappalyzer "$(command -v wappalyzer || true)" \
  --whatweb-offline "$(command -v whatweb || true)" \
  --offline-timeout 240 \
  --offline-max-files 40000 \
  --whatweb-max-targets 800 \
  --enable-web-scanners no \
  --enable-whatweb yes \
  --enable-nuclei no \
  --enable-nikto no \
  --enable-wapiti no \
  --enable-zap no \
  --enable-arachni no \
  --enable-skipfish no \
  --whatweb "/usr/bin/whatweb" \
  --nuclei "$(command -v nuclei || true)" \
  --nuclei-templates "$HOME/nuclei-templates" \
  --nuclei-rate 2.0 \
  --nuclei-concurrency 50 \
  --nuclei-severity "low,medium,high,critical" \
  --nuclei-tags "cves,exposure,misconfig,tech" \
  --scanners-timeout 900 \
  --scanners-max-targets 300 \
|& tee -a "$LOG_FILE"

# Dynamic Addons
echo ">>> [Step 2/4] Phase2 Addons (Playwright/Katana/Arjun/ParamSpider/APIs)"
"$PY" "$TOOLS/phase2_addons.py" \
  --root "$PHASE2_ROOT" \
  --allowed "$SCOPE_HOSTS" \
  --do-playwright yes \
  --do-katana yes \
  --do-arjun yes \
  --do-paramspider yes \
  --do-apis yes \
  --log-level INFO

# Sourcemap Unpacking
echo ">>> [Step 3/4] Unpacking sourcemaps"
"$PY" "$TOOLS/unpack_sourcemaps.py" --root "$PHASE2_ROOT"

# Advanced JS Semgrep scan (optional)
echo ">>> [Step 4/4] Advanced JS Semgrep scan (optional)"
RULES="${RULES:-$TOOLS/advanced_js_rules.yaml}"
TARGET="$PHASE2_ROOT/analysis/unpacked_sources"
OUTPUT_JSON="$PHASE2_ROOT/analysis/advanced_js_findings.json"

if [[ -x "$SEMGREP" && -f "$RULES" && -d "$TARGET" ]]; then
  "$SEMGREP" --config "$RULES" --json --quiet --output "$OUTPUT_JSON" "$TARGET" || true
  echo "    - Findings: $OUTPUT_JSON"
else
  echo "    - Skipping (semgrep/rules/target missing):"
  echo "      SEMGREP=$SEMGREP"
  echo "      RULES=$RULES"
  echo "      TARGET=$TARGET"
fi

echo "========================================================="
echo "[OK] Phase 2 Complete"
echo "   Results: $PHASE2_ROOT"
echo "   Log    : $LOG_FILE"
echo "========================================================="
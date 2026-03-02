# EnhancedRecon — Discovery ≠ Coverage

EnhancedRecon is a **coverage-first, 4-phase reconnaissance automation pipeline** designed for **authorized security testing**. It scales passive OSINT + archive mining, controlled harvesting, and offline forensics while enforcing a strict scope contract.

EnhancedRecon is the primary data-generation engine for the **ReconAggregator** Burp Suite Extension:
- ReconAggregator (Burp Extension): https://github.com/gr4ytips/ReconAggregator

---

## Repository layout (Important)

This repo contains a wrapper root and a **program root**:

- **Repo root (git clone folder):** `EnhancedRecon/`
- **Program root (scripts + scope + tools + outputs):** `EnhancedRecon/EnhancedRecon/` ✅ (a folder named `EnhancedRecon` inside the repo)

This matches how the runners compute `ROOT` (they set `ROOT` to the directory that contains the runner script).

You can run it in either of these ways:

### Option A (recommended): run from program root
```bash
git clone https://github.com/gr4ytips/EnhancedRecon.git
cd EnhancedRecon/EnhancedRecon
```

### Option B: run from repo root with a prefix
```bash
git clone https://github.com/gr4ytips/EnhancedRecon.git
cd EnhancedRecon
# then run scripts like: bash EnhancedRecon/run_phase0.sh
```

---

## Architecture: The 4‑Phase Pipeline

Each phase is runnable independently (good for manual gates / reviewer demos):

### Phase 0 — Scope Governance & Seeds (`run_phase0.sh`)
- Builds a scoped host inventory and baseline IP asset map.
- Uses strict **suffix allowlist** + **exact host allowlist**, minus denylist.
- Optional DNS/liveness enrichment (tunable via env).

### Phase 1 — Passive Recon & Archives (`run_phase1_passive.sh`)
- Uses third‑party datasets: Wayback/IA CDX, URLScan, OTX, CT, PDNS, Shodan, Censys, GitHub OSINT (as configured).
- Fetches **archive bodies from web archives** (not live targets) for offline review.
- Produces a scoped corpus of historical hostnames/URLs and seeds for Phase 2.

### Phase 2 — Harvest & Analysis (`run_phase2.sh`)
- Controlled, bounded interaction with **exact-scope hosts** only.
- JS DOM rendering (Playwright), crawling (Katana), parameter mining (Arjun/ParamSpider).
- Offline static analysis on downloaded assets (UCA, optional Semgrep, Retire.js, TruffleHog, etc).

### Phase 3 — Offline Intelligence (`run_phase3.sh`)
- Builds endpoint clusters, param hotspots, then‑vs‑now deltas, findings packs.
- Metadata forensics (embedded URLs, authors, mime mismatches).

---

## Prerequisites (high level)

- Linux (Kali/Ubuntu recommended)
- Bash + Python 3
- Go + Node.js (used by several recon tools)
- Internet access for installs and for Phases 0/2 (Phase 1 queries datasets; Phase 2 harvests)

> Installation is handled by the provided `*_install.sh` scripts.

---

## Installation

If you used **Option A**, you are already in the right place.

From **program root** (`EnhancedRecon/EnhancedRecon`):

```bash
# Optional bootstrap (fresh Kali box):
# - Installs go tooling + common deps quickly.
# - You can skip this if you run the phase installers below (they install what they need).
./install_external_tools.sh

# Phase installers (recommended):
./phase0_install.sh
./phase1_install.sh
./phase2_install.sh
./phase3_install.sh
```

If a `*_precheck.sh` exists for a phase, run it before the phase (or the runner may call it automatically):
```bash
./phase0_precheck.sh   # if present
./phase1_precheck.sh   # if present
./phase2_precheck.sh   # if present
./phase3_precheck.sh   # if present
```

---

## API Keys (only if you enable those integrations)

Export what you have; the pipeline will use available keys where supported:

```bash
export CHAOS_KEY="..."
export CHAOS_TOKEN="..."
export SECURITYTRAILS_KEY="..."
export CERTSPOTTER_TOKEN="..."
export SHODAN_API_KEY="..."
export CENSYS_API_KEY="..."
export IPINFO_API_KEY="..."
export URLSCAN_API_KEY="..."
export GITHUB_TOKEN="..."
```

---

## The “Optimal” Zsh Configuration

Add the following block to the bottom of your `~/.zshrc`. This uses Zsh’s `path` array (deduplicated), which automatically syncs with `PATH`.

```bash
# 1) Enable Zsh-native deduplication
typeset -U path PATH

# 2) Add Go and Manual Tools to the path array
# Zsh automatically handles the expansion of ~
path+=(
  ~/go/bin
  /usr/local/go/bin
  ~/tools/ParamSpider
  ~/tools/SecretFinder
  ~/tools/github-subdomains
)

# 3) Export the final result (Zsh syncs path and PATH automatically)
export PATH
```

---

## Verification

After saving your `~/.zshrc`, run:

```bash
source ~/.zshrc
echo $PATH | tr ':' '\n'
```

---

## Configuration: Scope Contract (Required)

EnhancedRecon is guardrails-first. It will refuse to run without scope inputs.

**Edit these files in the program root: `EnhancedRecon/EnhancedRecon/`**

> **CRITICAL FORMAT RULE:** put **one entry per line**. Lines starting with `#` are comments.

| File | Type | Meaning |
|---|---|---|
| `allowed_suffixes.txt` | Wildcard allowlist | Root domains where **all subdomains** are allowed (subject to denylist). Example: `example.com` allows `api.example.com` |
| `allowed_exact_hosts.txt` | Exact allowlist | Specific hostnames (optional `:port`) allowed even if not under suffixes. Example: `api.thirdparty.com:8443` |
| `out_of_scope_hosts.txt` | Denylist | Explicit exclusions that override all allowlists |
| `orgs.txt` | Seeds (optional) | Brand/org names used for Phase 0 expansion if enabled |
| `known_domains.txt` | Seeds (optional) | Extra seed domains used for Phase 0 expansion if enabled |

**Precedence rule:** `out_of_scope_hosts.txt` always wins.

### Minimal example (copy/paste)

`allowed_suffixes.txt`
```text
example.com
example.org
```

`allowed_exact_hosts.txt`
```text
api.thirdparty.com
api.thirdparty.com:8443
```

`out_of_scope_hosts.txt`
```text
support.example.com
old-admin.example.com
```

`orgs.txt`
```text
Acme Corp
Example Inc
```

`known_domains.txt`
```text
example.com
example.org
thirdparty.com
```

---

## Usage / Quick Start

Run sequentially from **program root** (`EnhancedRecon/EnhancedRecon`):

```bash
# Phase 0: build safe seeds and scoped host inventory
./run_phase0.sh

# Phase 1: passive OSINT + archive mining
./run_phase1_passive.sh

# Phase 2: controlled harvesting + analysis (ACTIVE)
./run_phase2.sh

# Phase 3: offline intelligence + forensics
./run_phase3.sh
```

---

## Outputs (Deterministic)

Default output locations (under program root):

- Phase 0: `out/`
  - `out/stepA/`, `out/stepBC/`, `out/stepD/` etc.
- Phase 1: `passive_enum_phase1/phase1_iter_1/`
  - `passive_enum_phase1/_scope_hosts_current.txt` (the exact scoped host list used)
  - `passive_enum_phase1/_seeds_current.txt` (legacy/compat seed list for Phase 2)
- Phase 2: `passive_enum_phase1/phase1_iter_1_phase2/`
  - includes `harvest/`, `analysis/`, `uca_out/` (varies by tooling)
- Phase 3: writes additional intelligence into the Phase 2 tree

Example skeleton:
```text
EnhancedRecon/EnhancedRecon/
  out/
    stepA/
    stepBC/
    stepD/
  passive_enum_phase1/
    phase1_iter_1/
      <per-domain passive outputs>
    _scope_hosts_current.txt
    _seeds_current.txt
    phase1_iter_1_phase2/
      harvest/
      analysis/
      uca_out/
      ...
```

---

## Tuning / Common Options

### Phase 0 (env toggles)
```bash
RUN_AMASS=no            # default no
CHECK_LIVE=yes          # StepD liveness checks
USE_KNOWN_DOMAINS=no    # include orgs.txt/known_domains.txt as additional seeds
STOP_AFTER=             # stepa | stepbc | stepd
RESOLVERS="1.1.1.1,8.8.8.8"
OUTDIR=".../out"        # optional override
```

### Phase 1 (archive range tuning)
```bash
YFROM=2025
YTO=2026
```

### Phase 2 (flags)
- Use a custom host allowlist instead of building from Phase 1:
```bash
./run_phase2.sh --scope-hosts /path/to/hosts.txt
```
- Filter to nonprod hosts only (dev/test/uat/stage/etc). If it selects 0, the runner aborts:
```bash
./run_phase2.sh --nonprod-only yes
```

### Phase 3 (point at any Phase 2 output tree)
```bash
PHASE2_OUTPUT_ROOT="/path/to/phase1_iter_1_phase2"
ALLOWED_FILE="/path/to/allowed_exact_hosts.txt"
./run_phase3.sh
```

### Phase 3 Truth Layer (safe HTTP validation; EXACT scope only)
This is optional and runs separately from `run_phase3.sh`.

```bash
# Usage:
./run_phase3_truth.sh <phase2_output_root> <allowed_exact_hosts_file>

# Example (default output tree + exact allowlist):
./run_phase3_truth.sh passive_enum_phase1/phase1_iter_1_phase2 allowed_exact_hosts.txt
```

Useful knobs (env overrides):
```bash
RESUME=yes CONCURRENCY=12 TIMEOUT=12 MAX_URLS=500 \
./run_phase3_truth.sh passive_enum_phase1/phase1_iter_1_phase2 allowed_exact_hosts.txt

# Run truth layer for a single domain folder (regex):
DOMAIN_FILTER='^api\\.example\\.com$' \
./run_phase3_truth.sh passive_enum_phase1/phase1_iter_1_phase2 allowed_exact_hosts.txt
```

Outputs (per domain folder):
- `passive_enum_phase1/phase1_iter_1_phase2/<domain>/analysis/truth/http_truth.jsonl`
- `passive_enum_phase1/phase1_iter_1_phase2/<domain>/analysis/truth/http_truth_summary.csv`

---
---

## Offline

```bash
export PHASE2_OUTPUT_ROOT="$PWD/passive_enum_phase1/phase1_iter_1_phase2"
./run_phase3.sh
```

This shows clustering, param hotspots, then‑vs‑now deltas, and metadata forensics without needing to perform active crawling live.

---

## Integrating with ReconAggregator (Burp Suite)

1) Open the **ReconAggregator** tab in Burp.
2) Go to **Settings**.
3) Set:
   - **Phase 1 Root** → `.../passive_enum_phase1/phase1_iter_1/`
   - **Phase 2 Root** → `.../passive_enum_phase1/phase1_iter_1_phase2/`
4) In **Import**, click **Run Full Backfill**.

---

## Troubleshooting (the common gotchas)

### “Scope hosts are empty”
- Ensure scope files are **one entry per line** (not space-separated).
- Confirm `out_of_scope_hosts.txt` isn’t excluding everything.

### `httpx` collision (python httpx vs ProjectDiscovery httpx)
Phase 2 tries hard to auto-detect the **ProjectDiscovery** `httpx`. If needed:
```bash
export HTTPX_BIN="$HOME/go/bin/httpx"
./run_phase2.sh
```

> Note: Phase 1 also performs ProjectDiscovery `httpx` detection and will avoid the python `httpx` CLI when possible.


### Playwright issues
If browser deps are missing, re-run `phase2_install.sh` and ensure Playwright browsers are installed per the script.

### Phase 3 truth layer fails with “httpx is required”
The truth layer (`phase3_truth_http.py`) needs the Python `httpx` package in the Phase 3 venv.

Fix:
```bash
./phase3_install.sh
# OR:
~/.venvs/phase3/bin/pip install httpx
```


### Missing optional URL exclude rules file
Phase 2 supports an optional `out_of_scope_url_rules.json`. If you want the knob, create an empty file:
```json
[]
```
If absent, Phase 2 proceeds without URL-rule filtering.

---

## Disclaimer & Legal

**Authorized testing only.** Phases 0/2 interact with systems and networks. You are responsible for ensuring you have explicit permission to test the assets defined in the scope contract and that your use complies with all applicable laws and program policies.

---

## Open Source Credits (Tooling Ecosystem)

EnhancedRecon orchestrates and integrates many community tools and public datasets, including (non-exhaustive):
- Archives & URL sources: Wayback / IA CDX, URLScan, AlienVault OTX, CT
- Discovery utilities: waybackurls, gau, subfinder, assetfinder, dnsx
- Intelligence: Shodan, Censys, SecurityTrails, ipinfo (when configured)
- Active tooling: ProjectDiscovery httpx, katana, arjun, paramspider, Playwright
- Offline analysis: UCA, optional Semgrep, Retire.js, TruffleHog, WhatWeb/Wappalyzer-style tooling

---

## AI Assistance Statement

Concept direction, system design, threat model assumptions, testing iterations, and the integration approach are authored entirely by **Shafeeque Olassery Kunnikkal**. AI tools were utilized strictly as engineering accelerators to assist with implementation details, including code refactoring, structural code review suggestions, and documentation synthesis. All operational capabilities, guardrails, and project claims are derived from hands-on, repeatable pipeline runs and rigorous manual inspection of generated artifacts by the author.

---

## Author

Shafeeque Olassery Kunnikkal (gr4ytips)

---

## License

Licensed under the Apache License, Version 2.0.

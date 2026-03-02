#!/usr/bin/env python3
"""
phase3_offline.py — Offline-only enrichments (PER-DOMAIN layout)

Outputs (under <domain>/analysis/offline):
  1) endpoint_clusters.csv
       - clustered patterns (/user/{id}?a,b) with counts, sources, first/last seen (by file mtime)
  2) then_vs_now.csv
       - archived routes vs current Phase-2 discovery & status (if logs available)
         columns: archived_url, host_alive_now, route_observed_now, now_status
  3) param_hotspots.csv
       - parameter degree + bipartite betweenness centrality + example URLs
  4) findings/<slug>/*
       - evidence packs for high-signal clusters not observed “now” (archived_urls.txt, current_candidates.txt, diff.json, risk.md)
  5) secrets.csv (optional)
       - consolidated secrets from TruffleHog / Gitleaks (offline scan of cc_bodies/ and uca_src/)
  6) js_dep_vulns.json (optional)
       - consolidated dependency vulns from retire.js / osv-scanner over uca_src/

Scope selection:
- Preferred: --allowed FILE   (one domain/subdomain per line, '#' comments ok)
- Optional:  --domain-filter REGEX  (further narrows selection if provided)

STRICTLY OFFLINE: reads only Phase-1/2 artifacts + local source trees; never touches targets.
"""

from __future__ import annotations
import argparse, sys, re, json, csv, time, subprocess, shutil, os
from pathlib import Path
from urllib.parse import urlparse, parse_qsl
from typing import Dict, List, Set, Tuple, Optional

DEBUG = True

# ----------------- Debug helpers -----------------
def dbg(msg: str):
    if DEBUG:
        print(f"[phase3_offline] {msg}", file=sys.stderr)

def stage(title: str):
    print(f"\n[phase3_offline] === {title} ===", file=sys.stderr)

# ----------------- I/O helpers -----------------
def read_lines(p: Path):
    if not p.exists(): return []
    return [ln.strip() for ln in p.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()]

def write_lines(p: Path, lines):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

def read_allowed(file: Path) -> set[str]:
    out: set[str] = set()
    if not file or not file.exists(): return out
    for ln in read_lines(file):
        if ln.startswith("#"): continue
        host = ln.strip().lower().rstrip(".")
        if host: out.add(host)
    return out

def which(binname: str) -> Optional[str]:
    """Resolve binaries with policy-aware fallbacks.

    Policy:
      - Prefer PATH resolution (shutil.which)
      - Then prefer ~/go/bin (or $GOBIN_DIR) for Go tools
    """
    if not binname:
        return None
    p = shutil.which(binname)
    if p:
        return p
    gobin = os.environ.get("GOBIN_DIR") or str(Path.home() / "go" / "bin")
    cand = Path(gobin) / binname
    if cand.exists() and os.access(str(cand), os.X_OK):
        return str(cand)
    return None

def _write_json(p: Path, obj) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(obj, indent=2), encoding="utf-8")

# ----------------- URL utils -----------------
WAYBACK_RX = re.compile(
    r"^https?://web\.archive\.org/web/\d+(?:[a-z_]+)?/(.+)$",
    re.I
)

def unwrap_wayback(u: str) -> str:
    '''
    Unwrap common Web Archive wrapper URLs:
      https://web.archive.org/web/<ts>/<scheme>://host/path?x=y
      https://web.archive.org/web/<ts>//host/path?x=y
    Returns the inner URL when detected; otherwise returns u unchanged.
    '''
    if not u:
        return u
    m = WAYBACK_RX.match(u.strip())
    if not m:
        return u
    inner = (m.group(1) or "").strip()
    if inner.startswith("//"):
        # scheme-relative; default to https
        return "https:" + inner
    return inner

def safe_parse_url(u: str):
    '''
    Parse a URL for offline analytics:
      - unwrap Wayback
      - ensure scheme if missing
    Returns ParseResult or None.
    '''
    if not u:
        return None
    u2 = unwrap_wayback(u.strip())
    if not u2:
        return None
    if u2.startswith("//"):
        u2 = "https:" + u2
    if not re.match(r"^https?://", u2, re.I):
        return None
    try:
        return urlparse(u2)
    except Exception:
        return None
def url_host(u: str) -> str:
    p = safe_parse_url(u)
    if not p:
        return ""
    try:
        return (p.hostname or "").lower().strip(".")
    except Exception:
        return ""
def collapse_tokens(path: str) -> str:
    # numeric ids
    path = re.sub(r"/\d{2,}", "/{id}", path)
    # hex blobs
    path = re.sub(r"/[a-fA-F0-9]{16,}", "/{hex}", path)
    # UUIDs
    path = re.sub(r"/[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", "/{uuid}", path)
    # dates
    path = re.sub(r"/\d{4}-\d{2}-\d{2}", "/{date}", path)
    path = re.sub(r"/\d{4}/\d{2}/\d{2}", "/{date}/", path)
    return path or "/"

def pattern_of(url: str) -> tuple[str,str,str,tuple[str,...]]:
    p = safe_parse_url(url)
    if not p:
        return ("http", "", "/", tuple())
    path = collapse_tokens(p.path or "/")
    qs_keys = tuple(sorted([k for k,_ in parse_qsl(p.query, keep_blank_values=True)]))
    scheme = (p.scheme or "http").lower()
    if scheme not in ("http", "https"):
        scheme = "http"
    return (scheme, (p.netloc or "").lower(), path, qs_keys)
def slugify(text: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9\-_.]+", "_", text)[:120]
    return s.strip("_") or "finding"

# ----------------- Inputs discovery -----------------
def find_input_files(ddir: Path):
    analysis = ddir / "analysis"
    candidates = [
        # Phase-1
        ddir/"wayback_clean.txt",
        ddir/"wayback_deep.txt",
        ddir/"ia_cdx_urls.txt",
        ddir/"wayback_multiarch.txt",
        ddir/"cc_routes.txt",
        ddir/"multiaddons_union.txt",
        # Phase-2 artifacts (offline reads)
        analysis/"katana_urls.txt",
        analysis/"rendered_endpoints_urls.txt",
        analysis/"unique_parameters.txt",
        analysis/"paramspider_params.txt",
        analysis/"live"/"live_urls.txt",
    ]
    candidates += list(ddir.glob("*.urls"))
    candidates += list(ddir.glob("*.links"))
    return [fp for fp in candidates if fp.exists()]

# ----------------- 1) Endpoint pattern clustering -----------------
def endpoint_clusters(ddir: Path, out_csv: Path) -> int:
    stage(f"{ddir.name}: Endpoint clustering")
    files = find_input_files(ddir)
    dbg(f"{ddir.name}: clustering from {len(files)} files")
    clusters: dict[str,int] = {}
    first_seen, last_seen, srcs = {}, {}, {}
    for fp in files:
        srcname = fp.name
        mtime = fp.stat().st_mtime
        for u in read_lines(fp):
            if not u.startswith("http"): continue
            scheme, host, path, keys = pattern_of(u)
            key = f"{scheme}://{host}{path}  ?{','.join(keys) if keys else ''}"
            clusters[key] = clusters.get(key, 0) + 1
            first_seen[key] = min(first_seen.get(key, mtime), mtime) if key in first_seen else mtime
            last_seen[key]  = max(last_seen.get(key, mtime), mtime) if key in last_seen else mtime
            srcs.setdefault(key, set()).add(srcname)
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["pattern","count","sources","first_seen_utc","last_seen_utc"])
        for pat, cnt in sorted(clusters.items(), key=lambda kv: -kv[1]):
            w.writerow([
                pat, cnt,
                ";".join(sorted(srcs.get(pat, []))),
                time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(first_seen[pat])),
                time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime(last_seen[pat])),
            ])
    dbg(f"{ddir.name}: wrote {out_csv.name} with {len(clusters)} patterns")
    return len(clusters)

# ----------------- 2) Then-vs-Now (status-aware) -----------------
def parse_status_from_lines(lines: List[str]) -> Dict[str,int]:
    """
    Heuristics to parse 'url -> status' from generic logs.
    Supports:
      - 'https://ex.. 200'
      - 'https://.. [200]'
      - CSV with url,status_code
      - JSONL lines with {"url": "...", "status": 200} or {"url":"...","status_code":200}
    """
    out: Dict[str,int] = {}
    for ln in lines:
        s = (ln or "").strip()
        if not s:
            continue

        # JSON object on line?
        if s.startswith("{") and s.endswith("}"):
            try:
                obj = json.loads(s)
                u = (obj.get("url") or obj.get("final_url") or obj.get("input") or obj.get("target") or "").strip()
                sc = obj.get("status") or obj.get("status_code") or obj.get("code") or obj.get("statusCode")
                if u and sc is not None:
                    try:
                        sci = int(sc)
                    except Exception:
                        sci = None
                    if sci is not None and 100 <= sci <= 999:
                        out[unwrap_wayback(u)] = sci
                        continue
            except Exception:
                pass

        # CSV url,status
        if "," in s and "http" in s.split(",", 1)[0]:
            parts = s.split(",")
            url = parts[0].strip()
            try:
                sc = int(parts[1])
                out[unwrap_wayback(url)] = sc
                continue
            except Exception:
                pass

        # plain "url [200]" or "url 200"
        m = re.search(r"^(https?://\S+)\s+\[?(\d{3})\]?$", s)
        if m:
            out[unwrap_wayback(m.group(1))] = int(m.group(2))

    return out
def load_phase2_status_map(analysis_dir: Path) -> Dict[str,int]:
    """
    Look for status-bearing logs created by Phase-2:
      - httpx*.json / .jsonl / .txt / .csv
      - whatweb*.txt (sometimes includes 200/301 etc.)
      - generic *.status* files
    We parse greedily and merge; later files can overwrite earlier.
    """
    status_map: Dict[str,int] = {}
    patterns = [
        "httpx*.json", "httpx*.jsonl", "httpx*.txt", "httpx*.csv",
        "whatweb*.txt", "whatweb*.csv",
        "*.status*", "*_status.*", "status_*.txt", "status.csv",
    ]
    files: List[Path] = []
    for pat in patterns:
        files.extend(list(analysis_dir.glob(pat)))
    files = [f for f in files if f.exists()]
    if not files:
        dbg("no status-bearing Phase-2 logs found")
        return status_map

    dbg(f"parsing status from {len(files)} files")
    for fp in files:
        try:
            if fp.suffix in (".json", ".jsonl"):
                lines = read_lines(fp)
                status_map.update(parse_status_from_lines(lines))
            else:
                status_map.update(parse_status_from_lines(read_lines(fp)))
        except Exception:
            continue
    return status_map

def then_vs_now(ddir: Path, out_csv: Path) -> int:
    stage(f"{ddir.name}: Then-vs-Now (status-aware)")
    archived_files = [
        ddir/"wayback_clean.txt", ddir/"wayback_deep.txt",
        ddir/"ia_cdx_urls.txt", ddir/"wayback_multiarch.txt", ddir/"cc_routes.txt"
    ]
    archived: Set[str] = set()
    for fp in archived_files:
        if fp.exists():
            for u in read_lines(fp):
                if u.startswith("http"):
                    archived.add(unwrap_wayback(u))

    analysis = ddir / "analysis"

    # Host-level "alive now" from Phase-2 live URL list.
    live_hosts = {url_host(u) for u in read_lines(analysis/"live"/"live_urls.txt") if url_host(u)}

    # Build observed route keys (host + collapsed path) from Phase-2.
    now_routes_raw = set(read_lines(analysis/"katana_urls.txt")) | set(read_lines(analysis/"rendered_endpoints_urls.txt"))
    now_route_keys: Set[tuple[str, str]] = set()
    for u in now_routes_raw:
        p = safe_parse_url(u)
        if not p:
            continue
        h = (p.hostname or "").lower().strip(".")
        if not h:
            continue
        now_route_keys.add((h, collapse_tokens(p.path or "/")))

    status_map = load_phase2_status_map(analysis)

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["archived_url", "host_alive_now", "route_observed_now", "now_status"])
        for u in sorted(archived):
            p = safe_parse_url(u)
            h = (p.hostname or "").lower().strip(".") if p else ""
            path_key = collapse_tokens(p.path or "/") if p else "/"
            observed = "yes" if (h and (h, path_key) in now_route_keys) else "no"

            # status: direct match; if none, try base URL (query stripped)
            sc = status_map.get(u)
            if sc is None:
                base = u.split("?", 1)[0]
                sc = status_map.get(base)

            w.writerow([u, "yes" if (h and h in live_hosts) else "no", observed, sc if sc is not None else ""])

    dbg(f"{ddir.name}: wrote {out_csv.name} over {len(archived)} archived urls")
    return len(archived)
def build_param_graph(ddir: Path, out_csv: Path) -> int:
    stage(f"{ddir.name}: Param hotspots (centrality)")
    try:
        import networkx as nx  # type: ignore
    except Exception:
        dbg("networkx not available; falling back to degree-only output")
        return param_hotspots_degree_only(ddir, out_csv)

    # Sources
    analysis = ddir/"analysis"
    url_files = [
        analysis/"unique_parameters.txt",
        analysis/"paramspider_params.txt",
        analysis/"katana_urls.txt",
        analysis/"rendered_endpoints_urls.txt",
    ]
    urls: List[str] = []
    for fp in url_files:
        if fp.exists():
            for ln in read_lines(fp):
                # lines may be "url  source:xxx"
                u = ln.split()[0]
                if u.startswith("http"):
                    urls.append(u)

    if not urls:
        dbg("no URLs for graph; writing empty file")
        with out_csv.open("w", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow(["param","degree","betweenness","endpoint_count","example_urls"])
        return 0

    # Build bipartite graph: Endpoint nodes (E: host+path pattern), Param nodes (P:param)
    G = nx.Graph()
    examples: Dict[str, Set[str]] = {}
    endpoints_seen: Dict[str, int] = {}

    for u in urls:
        try:
            p = urlparse(u)
        except Exception:
            continue
        host = (p.netloc or "").lower()
        path = collapse_tokens(p.path or "/")
        endpoint_node = f"E::{host}{path}"
        G.add_node(endpoint_node, bipartite=0)
        endpoints_seen[endpoint_node] = endpoints_seen.get(endpoint_node, 0) + 1
        for k,_ in parse_qsl(p.query, keep_blank_values=True):
            param_node = f"P::{k}"
            G.add_node(param_node, bipartite=1)
            G.add_edge(endpoint_node, param_node)
            examples.setdefault(k, set()).add(u[:200])

    # Compute param-node measures
    params = [n for n in G.nodes if str(n).startswith("P::")]
    deg_map = {n: G.degree(n) for n in params}
    # betweenness on full graph; inexpensive for usual sizes; falls back if too big
    try:
        btw_map = nx.betweenness_centrality(G, normalized=True)
    except Exception:
        btw_map = {n: 0.0 for n in params}

    rows = []
    for pn in params:
        k = pn.split("::",1)[1]
        degree = deg_map.get(pn, 0)
        betw = round(float(btw_map.get(pn, 0.0)), 6)
        # endpoints connected to this param
        endpoint_count = sum(1 for nbr in G.neighbors(pn) if str(nbr).startswith("E::"))
        exs = ";".join(list(examples.get(k, []))[:5])
        rows.append((k, degree, betw, endpoint_count, exs))

    # sort: degree desc, then betweenness desc
    rows.sort(key=lambda r: (-r[1], -r[2]))

    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["param","degree","betweenness","endpoint_count","example_urls"])
        for r in rows:
            w.writerow(r)

    dbg(f"{ddir.name}: wrote {out_csv.name} with {len(rows)} params")
    return len(rows)

def param_hotspots_degree_only(ddir: Path, out_csv: Path) -> int:
    analysis = ddir/"analysis"
    files = [analysis/"unique_parameters.txt", analysis/"paramspider_params.txt"]
    deg, examples = {}, {}
    for fp in files:
        if not fp.exists(): continue
        for ln in read_lines(fp):
            u = ln.split()[0]
            try:
                p = urlparse(u)
            except Exception:
                continue
            for k,_ in parse_qsl(p.query, keep_blank_values=True):
                deg[k] = deg.get(k, 0) + 1
                examples.setdefault(k, set()).add(u[:200])
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["param","degree","betweenness","endpoint_count","example_urls"])
        for k, v in sorted(deg.items(), key=lambda kv: -kv[1]):
            exs = ";".join(list(examples.get(k, []))[:5])
            w.writerow([k, v, 0.0, "", exs])
    dbg(f"{ddir.name}: wrote {out_csv.name} (degree-only) with {len(deg)} params")
    return len(deg)

# ----------------- 4) Evidence auto-pack -----------------
def build_findings(ddir: Path, clusters_csv: Path, then_now_csv: Path, min_count: int = 3) -> int:
    stage(f"{ddir.name}: Evidence auto-pack")
    analysis = ddir / "analysis"
    findings_dir = analysis / "offline" / "findings"
    created = 0

    # Archived URLs
    archived: Set[str] = set()
    for fp in [ddir/"wayback_clean.txt", ddir/"wayback_deep.txt", ddir/"ia_cdx_urls.txt", ddir/"wayback_multiarch.txt"]:
        if fp.exists():
            for u in read_lines(fp):
                if u.startswith("http"):
                    archived.add(unwrap_wayback(u))

    # Current URLs (Phase-2)
    now_urls = set(read_lines(analysis/"katana_urls.txt")) | set(read_lines(analysis/"rendered_endpoints_urls.txt"))
    now_urls = {unwrap_wayback(u) for u in now_urls if u.startswith("http")}

    if not clusters_csv.exists():
        return 0

    for row in csv.DictReader(clusters_csv.open("r", encoding="utf-8")):
        pat = row.get("pattern") or ""
        try:
            cnt = int(row.get("count") or 0)
        except Exception:
            cnt = 0

        if cnt < min_count or "://" not in pat:
            continue

        _scheme, rest = pat.split("://", 1)
        host = rest.split("/", 1)[0]
        path_part = "/" + (rest.split("/", 1)[1] if "/" in rest else "")
        path_part = path_part.split("  ?")[0]

        # Regex from collapsed path tokens (best-effort).
        rx = re.escape(path_part)
        rx = rx.replace("\\{id\\}", r"\\d{2,}")
        rx = rx.replace("\\{hex\\}", r"[A-Fa-f0-9]{16,}")
        rx = rx.replace("\\{uuid\\}", r"[0-9a-fA-F\\-]{36}")
        rx = rx.replace("\\{date\\}", r"\\d{4}(?:[-/]\\d{2}){2}")
        pat_rx = re.compile(rf"^https?://{re.escape(host)}{rx}", re.I)

        now_hits = [u for u in now_urls if pat_rx.search(u)]
        if now_hits:
            # Observed now → no evidence pack.
            continue

        slug = slugify(f"{host}{path_part}")
        fdir = findings_dir / slug
        fdir.mkdir(parents=True, exist_ok=True)

        arch_hits = [u for u in archived if pat_rx.search(u)]
        write_lines(fdir / "archived_urls.txt", arch_hits[:50])

        # Keep file for UI symmetry (empty list here by definition).
        write_lines(fdir / "current_candidates.txt", [])

        diff = {
            "pattern": pat,
            "cluster_count": cnt,
            "archived_count": len(arch_hits),
            "observed_now_count": 0,
        }
        (fdir / "diff.json").write_text(json.dumps(diff, indent=2), encoding="utf-8")

        risk = f"""Pattern: {pat}
Count (all sources): {cnt}
Archived examples: {min(len(arch_hits), 50)} listed in archived_urls.txt
Observed now: 0 (no Phase-2 URL matched this pattern)

Why it matters:
- Path looks templated; treat as candidate for BOLA/IDOR or legacy controller remnants.
- Try soft GET/HEAD from a safe host allowlist in Burp/OWASP ZAP with auth OFF.
- If 30x/403/500 now, check whether alt hosts/mirrors still dispatch this route.
"""
        (fdir / "risk.md").write_text(risk, encoding="utf-8")
        created += 1

    dbg(f"{ddir.name}: created {created} evidence packs under offline/findings/")
    return created
def run_trufflehog(root: Path, out_jsonl: Path) -> bool:
    """Run TruffleHog filesystem scan.

    TruffleHog CLI has changed across versions. We try the modern form first:
      trufflehog filesystem [flags] <path>
    and fall back to older variants.

    Always emits an artifact (even if empty) so downstream ingestion is stable.
    Returns True if the tool executed successfully (even with 0 findings).
    """
    binp = which("trufflehog")
    out_jsonl.parent.mkdir(parents=True, exist_ok=True)
    if not binp:
        dbg("trufflehog not found; skipping")
        out_jsonl.write_text("", encoding="utf-8")
        return False

    candidates = [
        # Modern: filesystem <path>
        [binp, "filesystem", "--no-update", "--json", str(root)],
        # Some builds accept 'file' instead of 'filesystem'
        [binp, "file", "--no-update", "--json", str(root)],
        # Legacy: --path <dir>
        [binp, "filesystem", "--no-update", "--json", "--path", str(root)],
    ]

    last_err = ""
    for cmd in candidates:
        try:
            cp = subprocess.run(cmd, text=True, capture_output=True, timeout=1800)
            # success is 0; treat 0 as success even if stdout empty
            if cp.returncode == 0:
                out_jsonl.write_text(cp.stdout or "", encoding="utf-8")
                return True
            last_err = (cp.stderr or cp.stdout or "").strip()
        except Exception as e:
            last_err = str(e)

    if last_err:
        dbg(f"trufflehog failed: {last_err[:300]}")
    out_jsonl.write_text("", encoding="utf-8")
    return False

def run_gitleaks(root: Path, out_json: Path) -> bool:
    """Run Gitleaks scan over a directory (no git required).

    Repo migration left some module-path mismatches, and CLI flags differ by version.
    We try modern flags first, then fall back.

    Always emits an artifact (even if empty) so downstream ingestion is stable.
    Returns True if the tool executed successfully (even with 0 findings).
    """
    binp = which("gitleaks")
    out_json.parent.mkdir(parents=True, exist_ok=True)
    # default empty JSON array
    out_json.write_text("[]\n", encoding="utf-8")

    if not binp:
        dbg("gitleaks not found; skipping")
        return False

    candidates = [
        # Modern: --source / --report-format / --report-path
        [binp, "detect", "--no-git", "--source", str(root), "--report-format", "json", "--report-path", str(out_json)],
        # Modern alt: --report-format json --report-path
        [binp, "detect", "--no-git", "--source", str(root), "--report-path", str(out_json), "--report-format", "json"],
        # Legacy: -s / -f / -r
        [binp, "detect", "--no-git", "-s", str(root), "-f", "json", "-r", str(out_json)],
    ]

    last_err = ""
    for cmd in candidates:
        try:
            cp = subprocess.run(cmd, text=True, capture_output=True, timeout=1800)
            # gitleaks may return 1 when findings are present; treat 0/1 as success
            if cp.returncode in (0, 1):
                # if tool didn't write report, but printed JSON to stdout, capture it
                if (not out_json.exists()) or out_json.stat().st_size == 0:
                    if cp.stdout and cp.stdout.lstrip().startswith(('[', '{')):
                        out_json.write_text(cp.stdout, encoding='utf-8')
                    else:
                        out_json.write_text("[]\n", encoding="utf-8")
                return True
            last_err = (cp.stderr or cp.stdout or "").strip()
        except Exception as e:
            last_err = str(e)

    if last_err:
        dbg(f"gitleaks failed: {last_err[:300]}")
    # keep empty artifact
    out_json.write_text("[]\n", encoding="utf-8")
    return False

def redact_secret(val: str) -> str:
    val = val or ""
    if len(val) <= 6: return "***"
    return val[:2] + "…" + val[-2:]

def portable_finding_file(file: str, root: Path) -> str:
    """Return a stable, move-safe file ref like 'uca_src/...' or 'cc_bodies/...'."""
    file = (file or "").strip()
    if not file:
        return ""
    try:
        p = Path(file)
        if p.is_absolute():
            try:
                rel = p.relative_to(root)
                return f"{root.name}/{rel.as_posix()}"
            except Exception:
                # Fall back: strip everything up to the last occurrence of '/<root.name>/'
                ss = file.replace('\\', '/')
                lo = ss.lower()
                anchor = f"/{root.name.lower()}/"
                ai = lo.rfind(anchor)
                if ai >= 0:
                    return ss[ai+1:]
                return ss
        else:
            ss = file.replace('\\', '/').lstrip('./')
            if ss.lower().startswith(root.name.lower() + "/"):
                return ss
            return f"{root.name}/{ss}"
    except Exception:
        return file

def consolidate_secrets(cc_dir: Path, uca_dir: Path, out_csv: Path, secrets_mode: str = "redacted") -> int:
    """
    Prefer scanning both cc_bodies/ and uca_src/. If dirs missing, skip.
    We run trufflehog + gitleaks if available, then emit a simple CSV.
    """
    stage(f"{out_csv.parent.parent.parent.name}: Secrets & dep intel — secrets")
    roots = [p for p in [cc_dir, uca_dir] if p and p.exists()]
    dbg("secrets scan roots: " + ", ".join(str(p) for p in roots)) 
    if not roots:
        dbg("no cc_bodies/ or uca_src/ present; skipping secrets step")
        return 0

    # Stable per-domain artifacts for ReconAggregator ingestion
    #   - analysis/offline/gitleaks_<root>.json
    #   - analysis/offline/trufflehog_<root>.jsonl
    out_dir = out_csv.parent
    truf_count = 0
    gitl_count = 0

    rows = []

    for root in roots:
        # TruffleHog
        tj = out_dir / f"trufflehog_{root.name}.jsonl"
        if run_trufflehog(root, tj):
            truf_count += 1
            for ln in read_lines(tj):
                try:
                    obj = json.loads(ln)
                    file = obj.get("SourceMetadata", {}).get("Data", {}).get("file","")
                    raw = obj.get("Raw","")
                    rule = obj.get("RuleID") or obj.get("Rule","")
                    fref = portable_finding_file(file, root)
                    if secrets_mode == "full":
                        rows.append(["trufflehog", rule or "", fref, raw])
                    elif secrets_mode == "both":
                        rows.append(["trufflehog", rule or "", fref, raw, redact_secret(raw)])
                    else:
                        rows.append(["trufflehog", rule or "", fref, redact_secret(raw)])
                except Exception:
                    continue
        # Gitleaks
        gj = out_dir / f"gitleaks_{root.name}.json"
        if run_gitleaks(root, gj):
            gitl_count += 1
            try:
                data = json.loads(gj.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    for item in data:
                        file = item.get("File","")
                        secret = item.get("Secret","")
                        rule = item.get("RuleID") or item.get("Rule") or ""
                        fref = portable_finding_file(file, root)
                        if secrets_mode == "full":
                            rows.append(["gitleaks", rule, fref, secret])
                        elif secrets_mode == "both":
                            rows.append(["gitleaks", rule, fref, secret, redact_secret(secret)])
                        else:
                            rows.append(["gitleaks", rule, fref, redact_secret(secret)])
            except Exception:
                pass

    if not rows:
        dbg("no secrets found or tools missing; writing header only")
        with out_csv.open("w", newline="", encoding="utf-8") as f:
            if secrets_mode == "full":
                csv.writer(f).writerow(["scanner","rule","file","match"])
            elif secrets_mode == "both":
                csv.writer(f).writerow(["scanner","rule","file","match","redacted_match"])
            else:
                csv.writer(f).writerow(["scanner","rule","file","redacted_match"])
        return 0

    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        if secrets_mode == "full":
            w.writerow(["scanner","rule","file","match"])
        elif secrets_mode == "both":
            w.writerow(["scanner","rule","file","match","redacted_match"])
        else:
            w.writerow(["scanner","rule","file","redacted_match"])
        for r in rows:
            w.writerow(r)

    dbg(f"wrote {out_csv.name} with {len(rows)} rows (trufflehog_runs={truf_count}, gitleaks_runs={gitl_count})")
    return len(rows)

def run_retirejs(uca_dir: Path, out_json: Path) -> bool:
    binp = which("retire")
    if not binp:
        dbg("retire.js not found; skipping")
        _write_json(out_json, {"skipped": "retire_missing"})
        return False
    # retire --path <dir> --outputformat json --outputfile <file>
    try:
        out_json.parent.mkdir(parents=True, exist_ok=True)
        cp = subprocess.run([binp, "--path", str(uca_dir), "--outputformat", "json", "--outputfile", str(out_json)],
                            text=True, capture_output=True, timeout=1800)
        return out_json.exists() and out_json.stat().st_size > 0
    except Exception as e:
        dbg(f"retire.js error: {e}")
        _write_json(out_json, {"error": "retire_exception", "detail": str(e)})
        return False

def run_osvscanner(uca_dir: Path, out_json: Path) -> bool:
    binp = which("osv-scanner")
    if not binp:
        dbg("osv-scanner not found; skipping")
        _write_json(out_json, {"skipped": "osv_scanner_missing"})
        return False
    # osv-scanner --recursive <dir> --json
    try:
        out_json.parent.mkdir(parents=True, exist_ok=True)
        cp = subprocess.run([binp, "--recursive", str(uca_dir), "--json"],
                            text=True, capture_output=True, timeout=1800)
        if cp.stdout and cp.stdout.strip():
            out_json.write_text(cp.stdout, encoding="utf-8")
            return True
        # No stdout: still emit artifact
        if cp.returncode == 0:
            _write_json(out_json, {"results": [], "note": "no_output"})
            return True
        _write_json(out_json, {"error": "osv_scanner_failed", "rc": cp.returncode, "stderr": (cp.stderr or "")[:2000]})
    except Exception as e:
        dbg(f"osv-scanner error: {e}")
        _write_json(out_json, {"error": "osv_scanner_exception", "detail": str(e)})
    return False

def consolidate_js_deps(uca_dir: Path, out_json: Path) -> int:
    """
    Run retire.js and/or osv-scanner on uca_src/ if it exists.
    Merge summaries into js_dep_vulns.json as {"retire": {...}, "osv": {...}}.
    """
    stage(f"{out_json.parent.parent.parent.name}: Secrets & dep intel — JS deps")
    dbg(f"JS deps scan root: {uca_dir}")
    if not uca_dir or not uca_dir.exists():
        dbg("uca_src/ not present; skipping JS deps step")
        # Always emit stable artifacts for ReconAggregator
        _write_json(out_json, {"retire": None, "osv": None, "note": "uca_src_missing"})
        _write_json(out_json.parent / "retire_raw.json", {"skipped": "uca_src_missing"})
        _write_json(out_json.parent / "osv_scanner_raw.json", {"skipped": "uca_src_missing"})
        return 0

    # Stable per-domain artifacts:
    #   - analysis/offline/retire_raw.json
    #   - analysis/offline/osv_scanner_raw.json
    rj = out_json.parent / "retire_raw.json"
    oj = out_json.parent / "osv_scanner_raw.json"

    reti_ok = run_retirejs(uca_dir, rj)
    osv_ok  = run_osvscanner(uca_dir, oj)

    result = {"retire": None, "osv": None}
    if reti_ok:
        try:
            result["retire"] = json.loads(rj.read_text(encoding="utf-8"))
        except Exception:
            result["retire"] = {"error": "parse"}
    if osv_ok:
        try:
            result["osv"] = json.loads(oj.read_text(encoding="utf-8"))
        except Exception:
            result["osv"] = {"error": "parse"}

    _write_json(out_json, result)
    dbg(f"wrote {out_json.name} (retire_ok={reti_ok}, osv_ok={osv_ok})")
    return (1 if reti_ok else 0) + (1 if osv_ok else 0)

# ----------------- main -----------------
def main():
    ap = argparse.ArgumentParser(description="Phase-3 offline enrichments (per-domain)")
    ap.add_argument("--root", required=True, help="Phase-1 output root that contains per-domain folders")
    ap.add_argument("--allowed", help="File with allowed domains/subdomains (one per line, supports # comments)")
    ap.add_argument("--domain-filter", default="", help="Optional regex to further narrow selected folders")
    ap.add_argument("--min-cluster", type=int, default=3, help="Min occurrences to create a finding")
    # feature toggles
    ap.add_argument("--do-secrets", choices=["yes","no"], default="yes", help="Run TruffleHog/Gitleaks if available (offline)")
    ap.add_argument("--secrets-mode", choices=["redacted","full","both"], default="redacted",
                    help="Secrets CSV output mode: redacted (default), full (store raw secrets), or both")
    ap.add_argument("--do-deps", choices=["yes","no"], default="yes", help="Run retire.js / osv-scanner over uca_src if available (offline)")
    ap.add_argument("--centrality", choices=["yes","no"], default="yes", help="Use NetworkX for bipartite centrality (else degree-only)")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    if not root.exists():
        print(f"root not found: {root}", file=sys.stderr); sys.exit(2)

    # Allowed-based selection (preferred)
    allowed_set: set[str] = set()
    if args.allowed:
        allowed_set = read_allowed(Path(args.allowed))
        dbg(f"loaded {len(allowed_set)} allowed hosts from {args.allowed}")

    # Optional regex filter (intersection)
    R = re.compile(args.domain_filter, re.I) if args.domain_filter else None

    def in_scope_folder(name: str) -> bool:
        n = name.lower().rstrip(".")
        if allowed_set:
            # Compliance default: treat allowed list as EXACT hosts only (no suffix expansion).
            return n in allowed_set
        return True  # if no allowed file provided, keep all; regex may still apply

    domains = []
    for d in sorted(root.iterdir()):
        if not d.is_dir(): continue
        if not in_scope_folder(d.name):
            dbg(f"skip (not in allowed): {d.name}")
            continue
        if R and not R.search(d.name):
            dbg(f"skip (regex filtered): {d.name}")
            continue
        domains.append(d)

    if not domains:
        print("no per-domain folders matched scope", file=sys.stderr); return

    for ddir in domains:
        print(f"\n[phase3_offline] >>> {ddir.name}")
        analysis = ddir/"analysis"
        offline = analysis/"offline"
        offline.mkdir(parents=True, exist_ok=True)

        # 1) Endpoint clusters
        cnt = endpoint_clusters(ddir, offline/"endpoint_clusters.csv")

        # 2) Then vs Now (status-aware)
        tvn = then_vs_now(ddir, offline/"then_vs_now.csv")

        # 3) Param–endpoint graph (centrality if available)
        if args.centrality == "yes":
            ph = build_param_graph(ddir, offline/"param_hotspots.csv")
        else:
            ph = param_hotspots_degree_only(ddir, offline/"param_hotspots.csv")

        # 4) Evidence packs
        packs = build_findings(ddir, offline/"endpoint_clusters.csv", offline/"then_vs_now.csv", min_count=args.min_cluster)

        # 5) Secrets & deps (optional, offline)
        cc_dir  = ddir / "cc_bodies"
        uca_dir = (ddir / "uca_src") if (ddir / "uca_src").exists() else (ddir / "analysis" / "uca_src")
        dbg(f"{ddir.name}: secrets roots → cc_bodies={'yes' if cc_dir.exists() else 'no'}, "
            f"uca_src={'yes' if (ddir/'uca_src').exists() else ('fallback' if (ddir/'analysis'/'uca_src').exists() else 'no')}")

        secrets_rows = 0
        if args.do_secrets == "yes":
            secrets_rows = consolidate_secrets(cc_dir, uca_dir, offline/"secrets.csv", secrets_mode=args.secrets_mode)

        deps_count = 0
        if args.do_deps == "yes":
            deps_count = consolidate_js_deps(uca_dir, offline/"js_dep_vulns.json")

        print(f"[phase3_offline] <<< {ddir.name} clusters={cnt} then_vs_now={tvn} params={ph} packs={packs} secrets_rows={secrets_rows} deps_ok={deps_count}")
        # Machine-readable per-domain summary for ReconAggregator ingestion.
        summary = {
            "domain": ddir.name,
            "clusters": cnt,
            "then_vs_now_rows": tvn,
            "param_rows": ph,
            "evidence_packs": packs,
            "secrets_rows": secrets_rows,
            "deps_reports": deps_count,
        }
        try:
            (offline / "offline_summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        except Exception:
            pass

    print("\n[phase3_offline] done")

if __name__ == "__main__":
    main()

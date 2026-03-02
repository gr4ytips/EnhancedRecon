#!/usr/bin/env python3
"""
phase2_addons.py — Additive, read-only Phase-2 helpers (PER-DOMAIN outputs)
ENHANCED v1.5: Added Runtime Secret Extraction (DOM) + API Schema Parsing

Adds (per domain):
  (1) JS-aware rendering via Playwright:
      -> screenshots
      -> DOM dumps
      -> runtime_secrets/*.json (localStorage/env vars) [NEW]
      -> <domain>/analysis/rendered_endpoints.jsonl
  (2) SPA crawl via katana (GET-only, depth=2) -> <domain>/analysis/katana_urls.txt
  (3) Parameter discovery:
      • Arjun (GET-only) -> <domain>/analysis/arjun_params.json
      • ParamSpider      -> <domain>/analysis/paramspider_params.txt
      Union -> <domain>/analysis/unique_parameters.txt
  (4) API schema sweeper (GET) -> <domain>/analysis/api_schemas/<host>.json
      [NEW] Parses downloaded schemas to extract endpoints -> <domain>/analysis/api_schema_endpoints.txt

Safety: ~2 rps global, <=2 parallel per host, GET/HEAD/OPTIONS only.
"""

from __future__ import annotations
import argparse, os, sys, json, time, subprocess, shutil, re
from pathlib import Path
from typing import List, Dict, Set, Tuple, Optional
import concurrent.futures as cf
from urllib.parse import urlparse

UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36"

# ----------------- logging helpers -----------------
_LEVELS = {"DEBUG": 10, "INFO": 20, "WARN": 30, "ERROR": 40}
LOG_LEVEL = _LEVELS["INFO"]

def _ts() -> str:
    return time.strftime("%H:%M:%S")

def _log(level: str, msg: str, domain: Optional[str] = None) -> None:
    if _LEVELS[level] < LOG_LEVEL:
        return
    dom = f"[{domain}] " if domain else ""
    print(f"[phase2_addons {level} { _ts() }] {dom}{msg}", file=sys.stderr, flush=True)

def log_info(msg: str, domain: Optional[str] = None) -> None:
    _log("INFO", msg, domain)

def log_debug(msg: str, domain: Optional[str] = None) -> None:
    _log("DEBUG", msg, domain)

def log_warn(msg: str, domain: Optional[str] = None) -> None:
    _log("WARN", msg, domain)

def log_error(msg: str, domain: Optional[str] = None) -> None:
    _log("ERROR", msg, domain)

# ----------------- small utils -----------------
def _read_lines(p: Path) -> List[str]:
    if not p.exists(): return []
    return [s.strip() for s in p.read_text(encoding="utf-8", errors="ignore").splitlines() if s.strip()]

def _write_lines(p: Path, lines: List[str]) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

def _which(x: Optional[str]) -> Optional[str]:
    if not x: return None
    w = shutil.which(x)
    if w: return w
    if Path(x).exists(): return str(Path(x))
    return None

def _url_host(u: str) -> str:
    try:
        return (urlparse(u).hostname or "").lower().strip(".")
    except Exception:
        return ""

def _scoped(url: str, allowed: Set[str], exact_only: bool = False) -> bool:
    try:
        h = urlparse(url).hostname or ""
    except Exception:
        h = ""
    h = (h or "").lower().strip().strip(".")
    if not h:
        return False
    if exact_only:
        return h in allowed
    # suffix / rdn style scope (legacy)
    return any(h == s or h.endswith("." + s) for s in allowed)

def _registrable_root(host: str) -> str:
    parts = host.lower().strip(".").split(".")
    if len(parts) >= 2:
        return ".".join(parts[-2:])
    return host.lower().strip(".")

# ----------------- alive urls per domain -----------------
def _alive_urls_for_domain(domain_dir: Path, folder_name: str, limit: int = 100) -> List[str]:
    """
    Source of truth: <domain>/analysis/live/live_urls.txt (Phase-2 liveness output).
    Filter so host == folder_name OR host endswith("." + folder_name).
    """
    live_file = domain_dir / "analysis" / "live" / "live_urls.txt"
    urls: List[str] = []
    for u in _read_lines(live_file):
        h = _url_host(u)
        if not h:
            continue
        if h == folder_name or h.endswith("." + folder_name):
            # ensure trailing slash for base URLs
            if not re.search(r"/\S", u) and not u.endswith("/"):
                u = u + "/"
            urls.append(u)
        if len(urls) >= limit:
            break
    # stable-uniq
    seen, out = set(), []
    for u in urls:
        if u not in seen:
            seen.add(u); out.append(u)
    return out

def _alive_hosts_for_domain(domain_dir: Path, folder_name: str, limit: int = 100) -> List[str]:
    hosts = {_url_host(u) for u in _alive_urls_for_domain(domain_dir, folder_name, limit)}
    return sorted(h for h in hosts if h)

# ----------------- (1) Playwright capture (Enhanced) -----------------
def run_playwright_capture(urls: List[str], out_jsonl: Path, max_tabs: int, rps: float, timeout_page: int, domain: str) -> None:
    """    Requires: pip install playwright && playwright install chromium

    NOTE: Playwright *sync* API uses greenlet and is **not thread-safe**.
    We therefore run capture sequentially in a single thread (respecting rps).

    Captures:
      1. XHR/fetch URLs
      2. Screenshots
      3. DOM Snapshots
      4. Runtime Secrets (localStorage, sessionStorage, selected window globals)
    """
    t0 = time.perf_counter()
    try:
        from playwright.sync_api import sync_playwright  # type: ignore
    except Exception:
        log_warn("Playwright not available; skipping", domain)
        return

    # Prepare output directories
    analysis_dir = out_jsonl.parent
    screenshots_dir = analysis_dir / "screenshots"
    dom_dir = analysis_dir / "dom_captures"
    secrets_dir = analysis_dir / "runtime_secrets"

    for d in [screenshots_dir, dom_dir, secrets_dir]:
        d.mkdir(parents=True, exist_ok=True)

    # Force single-thread for sync API safety
    if max_tabs and max_tabs > 1:
        log_warn(f"Playwright sync API is not thread-safe; forcing tabs=1 (requested {max_tabs})", domain)
    max_tabs = 1

    rate_sleep = 1.0 / max(rps, 0.1)
    total_seen = 0

    def _safe_name(url: str) -> str:
        return re.sub(r"\W+", "_", url)[:50]

    def _capture_for_url(browser, url: str) -> List[Dict[str, str]]:
        data: List[Dict[str, str]] = []
        safe = _safe_name(url)
        ctx = None
        try:
            ctx = browser.new_context(user_agent=UA, ignore_https_errors=True)
            page = ctx.new_page()

            # 1) Network interception
            def _on_req(req):
                rt = (req.resource_type or "").lower()
                if rt in ("xhr", "fetch"):
                    data.append({
                        "method": req.method,
                        "url": req.url,
                        "initiator": (req.headers.get("referer") or ""),
                        "type": rt,
                    })

            page.on("request", _on_req)

            # Navigate
            page.goto(url, wait_until="domcontentloaded", timeout=timeout_page * 1000)
            time.sleep(min(3, timeout_page / 2))  # Short hydration wait

            # 2) Screenshot
            try:
                page.screenshot(path=str(screenshots_dir / f"{safe}.png"))
            except Exception:
                pass

            # 3) DOM dump
            try:
                content = page.content()
                (dom_dir / f"{safe}.html").write_text(content, encoding="utf-8")
            except Exception:
                pass

            # 4) Runtime secret extraction
            try:
                runtime_data = page.evaluate(
                    """() => {
                        function dumpStorage(s) {
                            const o = {};
                            try {
                                for (let i = 0; i < s.length; i++) {
                                    const k = s.key(i);
                                    o[k] = s.getItem(k);
                                }
                            } catch (e) {}
                            return o;
                        }

                        const targets = ['env', 'config', 'settings', '__NEXT_DATA__', '__NUXT__', 'AppConfig'];
                        const window_vars = {};
                        targets.forEach(k => {
                            try { if (window[k]) window_vars[k] = window[k]; } catch (e) {}
                        });

                        return {
                            url: window.location.href,
                            localStorage: dumpStorage(window.localStorage),
                            sessionStorage: dumpStorage(window.sessionStorage),
                            global_vars: window_vars
                        };
                    }"""
                )

                has_data = False
                if runtime_data.get("localStorage") and len(runtime_data["localStorage"]) > 0:
                    has_data = True
                if runtime_data.get("sessionStorage") and len(runtime_data["sessionStorage"]) > 0:
                    has_data = True
                if runtime_data.get("global_vars") and len(runtime_data["global_vars"]) > 0:
                    has_data = True

                if has_data:
                    (secrets_dir / f"{safe}.json").write_text(json.dumps(runtime_data, indent=2), encoding="utf-8")
            except Exception as e:
                log_debug(f"Runtime secret extraction failed for {url}: {e}", domain)

        except Exception as e:
            log_debug(f"Playwright error for {url}: {e}", domain)
        finally:
            try:
                if ctx:
                    ctx.close()
            except Exception:
                pass
        return data

    log_info(f"Playwright: {len(urls)} URLs, tabs={max_tabs}, rps={rps}, timeout={timeout_page}s", domain)

    with sync_playwright() as pw:
        browser = None
        try:
            browser = pw.chromium.launch(headless=True)
            for i, url in enumerate(urls, 1):
                time.sleep(rate_sleep)
                chunk = _capture_for_url(browser, url)
                n = len(chunk or [])
                total_seen += n
                if chunk:
                    with out_jsonl.open("a", encoding="utf-8") as f:
                        for rec in chunk:
                            f.write(json.dumps(rec) + "\n")
                if i % 10 == 0 or n > 0:
                    log_debug(f"Playwright progress: {i}/{len(urls)} captured +{n}, total {total_seen}", domain)
        finally:
            try:
                if browser:
                    browser.close()
            except Exception:
                pass

    dt = time.perf_counter() - t0
    log_info(f"Playwright done: {total_seen} endpoints captured in {dt:.1f}s → {out_jsonl}")
# ----------------- (2) katana -----------------
def run_katana(seed_urls: List[str], out_file: Path, katana_bin: Optional[str], allowed: Set[str], domain: str) -> None:
    kb = _which(katana_bin or "katana")
    if not kb or not seed_urls:
        log_warn("katana not found or no seeds; skipping", domain); return
    scope_arg = ",".join(sorted(allowed)) if allowed else ""
    seeds = seed_urls[:500]
    cmd = [
        kb, "-silent",
        "-u", ",".join(seeds),
        "-depth", "2",
        "-js-crawl",
        "-automatic-form-fill", "false",
        "-http-method", "GET",
        "-rate-limit", "2",
        "-concurrency", "10",
        "-field", "url",
        "-scope", "rdn",
        "-rdn", scope_arg
    ]
    log_info(f"katana: seeds={len(seeds)}, scope={scope_arg or '(none)'}", domain)
    log_debug("katana cmd: " + " ".join(cmd), domain)
    t0 = time.perf_counter()
    try:
        cp = subprocess.run(cmd, text=True, capture_output=True, timeout=1800, check=False)
        if cp.stderr:
            log_debug(f"katana stderr (trimmed): {cp.stderr[:2000]}", domain)
        lines = [ln.strip() for ln in (cp.stdout or "").splitlines() if ln.strip()]
        before = len(lines)
        lines = [ln for ln in lines if _scoped(ln, allowed, exact_only=True)] if allowed else lines
        _write_lines(out_file, lines)
        dt = time.perf_counter() - t0
        log_info(f"katana done: {before} → {len(lines)} in-scope URLs in {dt:.1f}s → {out_file}", domain)
    except Exception as e:
        log_error(f"katana error: {e}", domain)

# ----------------- (3) Arjun & ParamSpider -----------------
def run_arjun(urls: List[str], out_json: Path, arjun_bin: Optional[str], domain: str) -> None:
    ab = _which(arjun_bin or "arjun")
    if not ab or not urls:
        log_warn("arjun not available or no targets; skipping", domain); return
    out_json.parent.mkdir(parents=True, exist_ok=True)
    targets = urls[:200]
    tmp = out_json.with_suffix(".targets.txt")
    _write_lines(tmp, targets)
    cmd = [ab, "-i", str(tmp), "-oJ", str(out_json), "-m", "GET"]
    log_info(f"Arjun: targets={len(targets)} (GET-only)", domain)
    log_debug("Arjun cmd: " + " ".join(cmd), domain)
    t0 = time.perf_counter()
    try:
        cp = subprocess.run(cmd, text=True, capture_output=True, timeout=1800, check=False)
        if cp.stderr:
            log_debug(f"Arjun stderr (trimmed): {cp.stderr[:2000]}", domain)
    except Exception as e:
        log_error(f"Arjun error: {e}", domain)
    dt = time.perf_counter() - t0
    # best-effort count
    found = 0
    try:
        data = json.loads(out_json.read_text(encoding="utf-8", errors="ignore") or "[]")
        if isinstance(data, list):
            for item in data:
                ps = item.get("params") or []
                if isinstance(ps, list): found += len(ps)
    except Exception:
        pass
    log_info(f"Arjun done: params≈{found} in {dt:.1f}s → {out_json}", domain)

def run_paramspider_for_domain(domain_host: str, out_txt: Path, paramspider_bin: Optional[str], domain: str) -> None:
    pb = _which(paramspider_bin or "paramspider")
    if not pb or not domain_host:
        log_warn("paramspider not available or no domain; skipping", domain); return
    out_txt.parent.mkdir(parents=True, exist_ok=True)

    collected: List[str] = []

    def _host(u: str) -> str:
        try:
            return (urlparse(u).hostname or "").lower().strip(".")
        except Exception:
            return ""

    # Try newer flags first
    new_cmd = [pb, "-d", domain_host, "--level", "low", "--exclude", "png,jpg,gif,svg,woff,ico"]
    legacy_cmd = [pb, "-d", domain_host, "-s"]

    log_info(f"ParamSpider: host={domain_host}", domain)
    log_debug("ParamSpider cmd (new attempt): " + " ".join(new_cmd), domain)

    t0 = time.perf_counter()
    try:
        cp = subprocess.run(new_cmd, text=True, capture_output=True, timeout=900, check=False)
        out = cp.stdout or ""
        err = (cp.stderr or "").lower()
        if "unrecognized" in err:
            log_debug("ParamSpider new flags unsupported; falling back to legacy streaming", domain)
            log_debug("ParamSpider cmd (legacy): " + " ".join(legacy_cmd), domain)
            cp = subprocess.run(legacy_cmd, text=True, capture_output=True, timeout=900, check=False)
            out = cp.stdout or ""
            for ln in out.splitlines():
                ln = ln.strip()
                if not ln.startswith("http"): continue
                if _host(ln) != domain_host:
                    continue
                if not re.search(r"\?.*=", ln): continue
                if re.search(r"\.(png|jpg|gif|svg|woff|ico)(\?|$)", ln, re.I): continue
                collected.append(ln + "  source:paramspider")
        else:
            for ln in out.splitlines():
                ln = ln.strip()
                if ln.startswith("http") and _host(ln) == domain_host:
                    collected.append(ln + "  source:paramspider")
    except Exception as e:
        log_error(f"ParamSpider error: {e}", domain)

    _write_lines(out_txt, collected)
    dt = time.perf_counter() - t0
    log_info(f"ParamSpider done: {len(collected)} URLs in {dt:.1f}s → {out_txt}", domain)

def union_params(arjun_json: Path, paramspider_txt: Path, out_union: Path, domain: str) -> None:
    t0 = time.perf_counter()
    seen: Set[str] = set()
    out: List[str] = []
    # Arjun JSON
    if arjun_json.exists():
        try:
            data = json.loads(arjun_json.read_text(encoding="utf-8", errors="ignore") or "[]")
            if isinstance(data, list):
                for item in data:
                    url = (item.get("url") or "").strip()
                    if not url: continue
                    ps = item.get("params") or []
                    if isinstance(ps, list):
                        for p in ps:
                            key = f"{url}?{p}"
                            if key not in seen:
                                out.append(key + "  source:arjun")
                                seen.add(key)
        except Exception as e:
            log_debug(f"Union: failed to parse Arjun JSON: {e}", domain)
    # ParamSpider
    for ln in _read_lines(paramspider_txt):
        if ln not in seen:
            out.append(ln); seen.add(ln)
    _write_lines(out_union, out)
    dt = time.perf_counter() - t0
    log_info(f"Union done: total unique {len(out)} → {out_union} ({dt:.1f}s)", domain)

# ----------------- (4) API schema sweeper (Enhanced) -----------------
API_CANDIDATES = ["/swagger.json", "/v2/api-docs", "/api-docs", "/openapi.json"]

def _http_get(url: str, timeout: int=10) -> Tuple[int, str]:
    import urllib.request, ssl
    ctx = ssl.create_default_context()
    req = urllib.request.Request(url, headers={"User-Agent": UA}, method="GET")
    try:
        with urllib.request.urlopen(req, timeout=timeout, context=(ctx if url.startswith("https://") else None)) as r:
            body = r.read()
            return r.status or 0, body.decode("utf-8", errors="ignore")
    except Exception:
        return 0, ""

def parse_and_extract_endpoints(file_path: Path) -> List[str]:
    """Helper to parse local JSON schema file and return endpoints"""
    endpoints = []
    try:
        content = file_path.read_text(encoding="utf-8", errors="ignore")
        data = json.loads(content)
        paths = data.get('paths', {})
        base_url = data.get('servers', [{}])[0].get('url', '')
        for path in paths.keys():
            full = f"{base_url.rstrip('/')}{path}"
            endpoints.append(full)
    except Exception:
        pass
    return endpoints

def sweep_api_schemas(hosts: List[str], out_dir: Path, out_list: Path, rps: float=2.0, domain: str = "") -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    found_urls: List[str] = []
    extracted_endpoints: List[str] = []
    
    delay = 1.0/max(rps, 0.1)
    log_info(f"API sweep: hosts={len(hosts)}, rps={rps}", domain)
    
    for i, h in enumerate(hosts[:200], 1):
        base = f"https://{h}"
        for path in API_CANDIDATES:
            url = base + path
            time.sleep(delay)
            code, body = _http_get(url, timeout=8)
            
            # Simple heuristic check
            if code in (200, 204) and (body.strip().startswith("{") or '"openapi"' in body.lower() or '"swagger"' in body.lower()):
                local_file = out_dir / f"{h}.json"
                local_file.write_text(body, encoding="utf-8")
                found_urls.append(url)
                log_debug(f"API found: {url}", domain)
                
                # [NEW] Immediate Extraction
                ends = parse_and_extract_endpoints(local_file)
                if ends:
                    log_debug(f"  -> Extracted {len(ends)} endpoints", domain)
                    extracted_endpoints.extend(ends)
                
                break # Found one for this host, move on
                
        if i % 10 == 0:
            log_debug(f"API sweep progress: {i}/{min(200, len(hosts))} hosts, found={len(found_urls)}", domain)
            
    _write_lines(out_list, found_urls)
    
    # Save extracted endpoints if any
    if extracted_endpoints:
        end_file = out_list.parent / "api_schema_endpoints.txt"
        _write_lines(end_file, sorted(set(extracted_endpoints)))
        log_info(f"API sweep done: {len(found_urls)} schemas, {len(extracted_endpoints)} parsed endpoints -> {out_list}", domain)
    else:
        log_info(f"API sweep done: {len(found_urls)} schemas found.", domain)

# ----------------- main -----------------
def main():
    ap = argparse.ArgumentParser(description="Non-intrusive Phase-2 addons (read-only, per-domain outputs)")
    ap.add_argument("--root", required=True, help="Phase-1 output root (contains per-domain folders)")
    ap.add_argument("--allowed", required=False, default="", help="Allowed domains file (one per line)")
    ap.add_argument("--do-playwright", choices=["yes","no"], default="yes")
    ap.add_argument("--do-katana", choices=["yes","no"], default="yes")

    # Back-compat switch: now only controls ParamSpider (NOT Arjun)
    ap.add_argument("--do-params", choices=["yes","no"], default="yes",
                    help="(deprecated) maps to ParamSpider only; use --do-paramspider/--do-arjun")

    # New independent toggles
    ap.add_argument("--do-arjun", choices=["yes","no"], default="no",
                    help="Enable Arjun (GET-only). Default: no")
    ap.add_argument("--do-paramspider", choices=["yes","no"], default="yes",
                    help="Enable ParamSpider. Default: yes")

    # API sweeper toggle (accept both spellings)
    ap.add_argument("--do-apis", "--do-api", dest="do_apis",
                    choices=["yes","no"], default="yes",
                    help="Enable API schema sweeper (GET). Default: yes")

    # tool bins
    ap.add_argument("--katana", default="katana")
    ap.add_argument("--arjun", default="arjun")
    ap.add_argument("--paramspider", default="paramspider")

    # perf/safety
    ap.add_argument("--rps", type=float, default=2.0)
    ap.add_argument("--per-host-par", type=int, default=2)
    ap.add_argument("--timeout-page", type=int, default=15)

    # caps per-domain
    ap.add_argument("--alive-cap", type=int, default=100, help="Max alive URLs per domain to sample")

    # logging
    ap.add_argument("--log-level", choices=["DEBUG","INFO","WARN","ERROR"], default="INFO")

    args = ap.parse_args()
    global LOG_LEVEL
    LOG_LEVEL = _LEVELS[args.log_level]

    root = Path(args.root).resolve()
    if not root.exists() or not root.is_dir():
        log_error(f"root not found: {root}")
        sys.exit(2)

    # allowed suffixes (used for katana scoping only)
    if args.allowed:
        allowed_set = set(_read_lines(Path(args.allowed)))
        log_debug(f"Loaded allowed suffixes: {len(allowed_set)}")
    else:
        candidates = []
        for d in root.iterdir():
            if d.is_dir():
                candidates.append(_registrable_root(d.name))
        allowed_set = set(sorted(set(candidates)))
        log_debug(f"Derived allowed suffixes from folder names: {len(allowed_set)}")

    # Effective toggles
    do_arjun = (args.do_arjun == "yes")  # default no
    do_paramspider = (args.do_paramspider == "yes") and (args.do_params == "yes")

    domain_dirs = [d for d in sorted(root.iterdir()) if d.is_dir()]
    if not domain_dirs:
        log_warn("no per-domain folders under root; nothing to do")
        return

    log_info(f"Starting Phase-2 addons for {len(domain_dirs)} domain folders under {root}")

    for ddir in domain_dirs:
        domain_name = ddir.name  # exact folder name (may be subdomain)
        analysis_dir = ddir / "analysis"
        analysis_dir.mkdir(parents=True, exist_ok=True)

        # per-domain allowed set for katana scope
        per_allowed = {s for s in allowed_set
                       if domain_name==s or domain_name.endswith("."+s)
                          or s.endswith("."+_registrable_root(domain_name))
                          or s==_registrable_root(domain_name)}
        if not per_allowed:
            per_allowed = {domain_name, _registrable_root(domain_name)}

        # Alive URLs/hosts for this domain (Phase-2 liveness ONLY)
        alive_urls = _alive_urls_for_domain(ddir, domain_name, limit=args.alive_cap)
        alive_hosts = _alive_hosts_for_domain(ddir, domain_name, limit=args.alive_cap)
        log_info(f"Domain init: live_urls={len(alive_urls)}, live_hosts={len(alive_hosts)}", domain_name)

        if not alive_urls:
            log_warn("no live URLs in analysis/live/live_urls.txt; skipping active steps", domain_name)
            log_info("✓", domain_name)
            continue

        # (1) Playwright (per-domain) - ENHANCED
        if args.do_playwright == "yes":
            out_jsonl = analysis_dir / "rendered_endpoints.jsonl"
            run_playwright_capture(alive_urls[:min(100, len(alive_urls))], out_jsonl,
                                   max_tabs=max(1, args.per_host_par), rps=max(0.5, args.rps),
                                   timeout_page=args.timeout_page, domain=domain_name)
            # flatten captured URLs
            flat = []
            if out_jsonl.exists():
                for ln in _read_lines(out_jsonl):
                    try:
                        obj = json.loads(ln)
                        u = obj.get("url") or ""
                        if u: flat.append(u)
                    except Exception:
                        continue
            _write_lines(analysis_dir / "rendered_endpoints_urls.txt", sorted(set(flat)))
            log_debug(f"Flattened rendered endpoints: {len(set(flat))}", domain_name)

        # (2) katana (per-domain)
        if args.do_katana == "yes":
            run_katana(alive_urls[:min(150, len(alive_urls))],
                       analysis_dir / "katana_urls.txt", args.katana, per_allowed, domain=domain_name)

        # (3a) Arjun (per-domain, independent)
        if do_arjun:
            seeds = [u for u in alive_urls if re.search(r"/(api|v\d+|graphql|openapi|swagger)(/|$|\?)", u, re.I)]
            if not seeds:
                seeds = alive_urls[:min(80, len(alive_urls))]
            log_debug(f"Arjun seeds={len(seeds)}", domain_name)
            run_arjun(seeds, analysis_dir / "arjun_params.json", args.arjun, domain=domain_name)

        # (3b) ParamSpider (per-domain, EXACT host)
        if do_paramspider:
            run_paramspider_for_domain(domain_name, analysis_dir / "paramspider_params.txt", args.paramspider, domain=domain_name)

        # (3c) Union (runs if either side produced output)
        union_params(analysis_dir / "arjun_params.json",
                     analysis_dir / "paramspider_params.txt",
                     analysis_dir / "unique_parameters.txt",
                     domain=domain_name)

        # (4) API schema sweeper (per-domain) - ENHANCED
        if args.do_apis == "yes" and alive_hosts:
            sweep_api_schemas(alive_hosts, analysis_dir / "api_schemas",
                              analysis_dir / "api_candidates.txt", rps=max(0.5, args.rps), domain=domain_name)

        log_info("✓", domain_name)

    log_info("All done (per-domain outputs).")

if __name__ == "__main__":
    main()
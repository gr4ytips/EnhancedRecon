#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
harvest_and_scan.py - Phase-2 harvester with Phase-1 merge + seed-hosts + auto-discover & interactive picker
Updated: add DEBUG tracing to nearly every function + split analysis (pre/archived vs post/live) + optional JS tools
"""

import argparse
import asyncio
import aiohttp
import aiofiles
import os
import re
import time
import base64
import json
import urllib.parse
from urllib.parse import urlparse
from pathlib import Path
import shutil
import logging
import subprocess
import sys
import random
from typing import Optional, List, Dict, Tuple, Set
from email.utils import parsedate_to_datetime
from urllib import robotparser
import fnmatch
from datetime import datetime, timezone


def _now_utc_iso() -> str:
    """UTC timestamp in ISO-8601 with trailing 'Z'."""
    return datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')

import platform
from offline_analyzers import run_offline_analyzers
from post_scanners import run_post_scanners

# -------- logging --------
log = logging.getLogger("phase2")
handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
log.addHandler(handler)
log.setLevel(os.getenv("RECON_LOG_LEVEL", "INFO").upper())

# -------------------------------------------
# trace decorator to help with debug coverage
# -------------------------------------------

def _safe_preview(v):
    try:
        s = str(v)
    except Exception:
        return "<unprintable>"
    s = s.replace("\n", "\\n")
    return s if len(s) <= 120 else s[:117] + "..."


def trace(func):
    if asyncio.iscoroutinefunction(func):
        async def wrapper(*args, **kwargs):
            if log.isEnabledFor(logging.DEBUG):
                arg_preview = ", ".join(_safe_preview(a) for a in args[:3])
                log.debug(f"-> {func.__name__}({arg_preview}{', ...' if len(args) > 3 or kwargs else ''})")
            t0 = time.perf_counter()
            try:
                res = await func(*args, **kwargs)
                return res
            finally:
                dt = (time.perf_counter() - t0) * 1000
                log.debug(f"<- {func.__name__} dt={dt:.1f}ms")
        return wrapper
    else:
        def wrapper(*args, **kwargs):
            if log.isEnabledFor(logging.DEBUG):
                arg_preview = ", ".join(_safe_preview(a) for a in args[:3])
                log.debug(f"-> {func.__name__}({arg_preview}{', ...' if len(args) > 3 or kwargs else ''})")
            t0 = time.perf_counter()
            try:
                return func(*args, **kwargs)
            finally:
                dt = (time.perf_counter() - t0) * 1000
                log.debug(f"<- {func.__name__} dt={dt:.1f}ms")
        return wrapper


# ---------------------------
# Small time + URL normalizers
# ---------------------------

def utcnow_z() -> str:
    """UTC now as RFC3339-ish Z string, without deprecated utcnow."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


def normalize_url_line(s: str) -> str:
    """Normalize input URL lines so we never fetch archive wrapper hosts.
    - Unwrap common Wayback URLs to the embedded real URL
    - Trim whitespace and common trailing punctuation
    - Drop URL fragments
    - If schemeless host/path, prefix https://
    """
    s = (s or "").strip()
    if not s:
        return ""
    # strip common trailing junk from copy/paste
    s = s.strip().strip(")>].,;\"'")
    # unwrap web.archive wrapper -> keep the embedded real URL at the end
    if "web.archive.org/web/" in s:
        m = re.search(r"(https?://[^\s]+)$", s)
        if m:
            s = m.group(1).strip()
    # remove fragments (never sent to servers)
    try:
        u = urllib.parse.urlsplit(s)
        if u.scheme and u.netloc:
            s = urllib.parse.urlunsplit(u._replace(fragment=""))
    except Exception:
        pass
    # schemeless host/path -> assume https
    if "://" not in s:
        # looks like host[:port][/path...]
        if re.match(r"^[A-Za-z0-9.-]+(?::\d+)?(?:/.*)?$", s):
            s = "https://" + s
    return s
# ---------------------------
# Helpers / constants
# ---------------------------

INTERESTING_EXTS_DEFAULT: Set[str] = {
    ".js", ".jsp", ".jspx", ".html", ".ts", ".php", ".vue",
    ".jsx", ".json", ".map", ".css", ".xml",
    ".mjs", ".cjs", ".tsx", ".xhtml", ".svg", ".webmanifest",
}
PATH_HINTS = tuple(sorted(INTERESTING_EXTS_DEFAULT, key=len, reverse=True))  # longer first

SM_COMMENT_RE = re.compile(
    r"(?://[@#]\ssourceMappingURL\s=\s*)(?P<url>\S+)",
    re.IGNORECASE,
)

CONTENT_TYPE_MAP = {
    "application/javascript": ".js",
    "text/javascript": ".js",
    "application/x-javascript": ".js",
    "text/html": ".html",
    "application/xhtml+xml": ".html",
    "application/json": ".json",
    "text/json": ".json",
    "text/css": ".css",
    "application/xml": ".xml",
    "text/xml": ".xml",
    "image/svg+xml": ".svg",
    # NEW: common binaries you explicitly allow via --extra-exts
    "application/pdf": ".pdf",
    "application/msword": ".doc",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.ms-excel": ".xls",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    "application/vnd.ms-powerpoint": ".ppt",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
    "application/zip": ".zip",
    "image/jpeg": ".jpg",
    "image/png": ".png",
    "image/tiff": ".tiff",
    "image/webp": ".webp",
    "image/svg+xml": ".svg",
}

CANONICAL_URL_FILES = {
    "wayback_clean.txt", "wayback_deep.txt", "cc_urls.txt",
    "feed_urls.txt", "pkg_urls.txt", "containers_urls.txt",
    "mobile_endpoints.txt", "client_urls.txt",
    "ia_cdx_urls.txt",  # NEW
    "otx_urls.txt",     # NEW
    "urlscan_urls.txt", # NEW
    # optional:
    # "wayback_raw.txt",
}

CANONICAL_HOST_FILES = {
    "ct_domains.txt", "ct_alt_names.txt", "pdns_hostnames.txt",
    "fdns_hosts.txt", "historical_dns.txt", "shodan_hostnames.txt",
}

# ---------------------------
# Scope helpers
# ---------------------------

def _normalize_host(url_or_host: str) -> str:
    """Normalize a host from either a host string or a URL-like string.
    Robust to: schemeless host/path, host:port, and common archive wrapper URLs.
    Returns lowercase host without port/wildcards/trailing dot, or '' if none.
    """
    try:
        s = (url_or_host or '').strip()
        if not s:
            return ''
        # Unwrap common archive wrapper URLs (keep it simple and safe)
        if 'web.archive.org/web/' in s:
            # e.g. https://web.archive.org/web/2020*/https://accounts.fidelity.com/x
            urls = re.findall(r'(https?://[^\s]+)', s)
            if urls:
                s = urls[-1]
        # If it's a full URL, parse hostname; else treat as host/path
        if '://' in s:
            host = urlparse(s).hostname or ''
        else:
            host = s.split('/')[0]
        host = host.split(':')[0].lower().strip().strip('.')
        host = re.sub(r'^\*\.', '', host)
        host = re.sub(r'^\.', '', host)
        return host
    except Exception:
        return ''

@trace
def load_scope(scope_file: str) -> set:
    t0 = time.perf_counter()
    scopes = set()
    with open(scope_file, encoding='utf-8', errors='ignore') as f:
        for line in f:
            raw = line.strip()
            if not raw or raw.lstrip().startswith('#'):
                continue
            h = _normalize_host(raw)
            if h:
                scopes.add(h)
    log.info(
        f'Loaded scope entries: {len(scopes)} from {scope_file} in {int((time.perf_counter()-t0)*1000)} ms'
    )
    return scopes


@trace
def utc_now_iso() -> str:
    """RFC3339-ish UTC timestamp with 'Z'."""
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")


@trace
def in_scope(url_or_host: str, allowed_domains: set) -> bool:
    """Exact-host scope check, but robust to:
    - schemeless URL lines like: host/path
    - host:port
    - web archive wrapper URLs where the real URL is embedded in the path
    """
    try:
        s = (url_or_host or "").strip()
        if not s:
            return False

        # unwrap common archive wrapper URLs (keep it simple and safe)
        # e.g. https://web.archive.org/web/2020*/https://accounts.fidelity.com/x
        if "web.archive.org/web/" in s:
            mm = re.search(r"(https?://[^\s]+)$", s)
            if mm:
                s = mm.group(1)

        if "://" in s:
            host = urllib.parse.urlparse(s).hostname or ""
        else:
            # schemeless: host/path OR just host
            host = s.split("/")[0]

        host = host.split(":")[0].lower().strip().strip(".")
        if not host:
            return False
        return host in {d.lower().strip().strip('.') for d in allowed_domains}
    except Exception:
        return False

def load_exclude_url_rules(path: Optional[str]) -> list:
    """
    Load path-level exclusion rules from JSON.
    Expected format: list of objects like {"host": "api.fidelity.com", "path_regex": "^/foo/v1.*"}
    host match is exact (case-insensitive). path_regex is applied to URL path (no query).
    """
    if not path:
        return []
    p = Path(path)
    if not p.exists():
        log.warning(f"exclude-url-rules-json not found: {path}")
        return []
    try:
        data = json.loads(p.read_text("utf-8", errors="ignore"))
        rules = []
        if isinstance(data, list):
            for r in data:
                if not isinstance(r, dict):
                    continue
                host = str(r.get("host") or "").lower().strip().strip(".")
                rx = str(r.get("path_regex") or r.get("file") or "").strip()
                if host and rx:
                    try:
                        rules.append((host, re.compile(rx)))
                    except re.error:
                        log.warning(f"Bad path_regex in exclude rule for host={host}: {rx}")
        return rules
    except Exception as e:
        log.warning(f"Failed to parse exclude-url-rules-json={path}: {e!r}")
        return []

def excluded_by_url_rules(url: str, rules: list) -> bool:
    if not rules:
        return False
    try:
        pu = urllib.parse.urlparse(url)
        host = (pu.hostname or "").lower().strip().strip(".")
        path = pu.path or "/"
        for h, rx in rules:
            if host == h and rx.search(path):
                log.debug(f"excluded_by_url_rules host={host} path={path} rule={rx.pattern}")
                return True
    except Exception:
        return False
    return False

@trace
async def allowed_by_robots(url: str, user_agent: str, respect: bool = True) -> bool:
    if not respect:
        return True
    parsed = urllib.parse.urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}/robots.txt"
    rp = robotparser.RobotFileParser()
    try:
        rp.set_url(base)
        rp.read()
        can = rp.can_fetch(user_agent, url)
        log.debug(f"robots {base} can={can} url={url}")
        return can
    except Exception as e:
        log.debug(f"robots read fail: {e}")
        return False

# ---------------------------
# Filename/url helpers
# ---------------------------

@trace
def safe_filename(url: str) -> str:
    parsed = urllib.parse.urlparse(url)
    enc = base64.urlsafe_b64encode((parsed.path + "?" + (parsed.query or "")).encode()).decode()[:64]
    scheme = parsed.scheme or "http"
    return f"{scheme}{parsed.netloc}{enc}"


@trace
def guess_ext_from_headers(headers_text: str) -> str:
    m = re.search(r"(?i)^content-type:\s*([^\s;]+)", headers_text, re.MULTILINE)
    if not m:
        return ".txt"
    ctype = m.group(1).lower().strip()
    return CONTENT_TYPE_MAP.get(ctype, ".txt")


@trace
def guess_ext_from_url(url: str) -> str:
    path = urllib.parse.urlparse(url).path.lower()
    for hint in PATH_HINTS:
        if path.endswith(hint) or hint in path:
            return hint
    return ".txt"

# ---------------------------
# URL/host file helpers (Phase-1 integration)
# ---------------------------

@trace
def _read_lines(path: Path) -> List[str]:
    out: List[str] = []
    with open(path, encoding="utf-8", errors="ignore") as f:
        for line in f:
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            out.append(s)
    return out


@trace
def _union_url_files(files: List[str]) -> List[str]:
    bag: Set[str] = set()
    for fp in files:
        for s in _read_lines(Path(fp)):
            u = normalize_url_line(s)
            if u:
                bag.add(u)
    return sorted(bag)


@trace
def _scope_intersect_hosts(hosts: Set[str], allowed: Set[str]) -> Set[str]:
    allowed_lc = {d.lower() for d in allowed}
    out: Set[str] = set()
    for h in hosts:
        nh = _normalize_host(h)
        if nh and nh in allowed_lc:
            out.add(nh)
    return out


@trace
def _expand_seed_hosts_to_urls(hosts_file_list: List[str], safe_paths: List[str],
                               allowed: Set[str]) -> List[str]:
    raw_hosts: Set[str] = set()
    for hf in hosts_file_list:
        for s in _read_lines(Path(hf)):
            raw_hosts.add(s.strip())
    kept = _scope_intersect_hosts(raw_hosts, allowed)

    urls: Set[str] = set()
    norm_paths: List[str] = []
    for p in safe_paths:
        p = p.strip()
        if not p:
            continue
        if not p.startswith("/"):
            p = "/" + p
        norm_paths.append(p)

    for h in kept:
        for p in norm_paths:
            urls.add(f"https://{h}{p}")
    return sorted(urls)


@trace
def _infer_domain_label(args, allowed: Set[str]) -> Optional[str]:
    if args.domain:
        return args.domain.strip()
    if len(allowed) == 1:
        return next(iter(allowed))
    return None

# ---------------------------
# Auto-discover + interactive picker
# ---------------------------

@trace
def _is_tty() -> bool:
    try:
        return sys.stdin.isatty()
    except Exception:
        return False


@trace
def _match_any(name: str, globs: List[str]) -> bool:
    for g in globs:
        if fnmatch.fnmatch(name, g):
            return True
    return False


@trace
def _discover_phase1_files(
    base_dir: Path,
    include_globs: List[str],
    include_host_globs: List[str],
    domain_filter: Optional[str]
) -> Dict[str, Dict[str, List[Path]]]:
    out: Dict[str, Dict[str, List[Path]]] = {}
    if not base_dir.exists():
        return out

    for root, dirs, files in os.walk(base_dir):
        root_p = Path(root)
        try:
            rel = root_p.relative_to(base_dir)
        except ValueError:
            continue
        parts = rel.parts
        if not parts:
            continue
        domain = parts[0]

        if domain_filter:
            if domain_filter.startswith("^") or ("(" in domain_filter and ")" in domain_filter):
                try:
                    if not re.search(domain_filter, domain, re.IGNORECASE):
                        continue
                except re.error:
                    if not fnmatch.fnmatch(domain, domain_filter):
                        continue
            else:
                if not fnmatch.fnmatch(domain, domain_filter):
                    continue

        url_files: List[Path] = []
        host_files: List[Path] = []

        for fname in files:
            lower = fname.lower()
            p = root_p / fname
            if lower in CANONICAL_URL_FILES or _match_any(lower, include_globs):
                url_files.append(p)
            elif lower in CANONICAL_HOST_FILES or _match_any(lower, include_host_globs):
                host_files.append(p)

        if url_files or host_files:
            d = out.setdefault(domain, {"url_files": [], "host_files": []})
            d["url_files"].extend(url_files)
            d["host_files"].extend(host_files)

    return out


@trace
def _fmt_size(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024.0:
            return f"{n:.0f}{unit}"
        n /= 1024.0
    return f"{n:.0f}TB"


@trace
def _count_lines(p: Path, cap: int = 2_000_000) -> int:
    try:
        i = 0
        with open(p, 'rb') as f:
            for _ in f:
                i += 1
                if i > cap:
                    break
        return i
    except Exception:
        return 0

# (Interactive picker left mostly un-instrumented for readability during selection)

def _prompt_picker(domain: str, url_files: List[Path], host_files: List[Path]) -> Tuple[List[Path], List[Path]]:
    print(f"\n=== Select inputs for {domain} ===")
    items: List[Tuple[str, Path, str]] = []
    idx = 1
    for p in sorted(url_files):
        items.append(("url", p, f"[{idx}] URL {p.name} ({_count_lines(p)} lines)"))
        idx += 1
    for p in sorted(host_files):
        items.append(("host", p, f"[{idx}] HOST {p.name} ({_count_lines(p)} lines)"))
        idx += 1

    for _, _, line in items:
        print("  " + line)
    print("  ---")
    print("  Enter: numbers (e.g., 1,3,5), ranges (2-6), 'all', 'none'")
    print("  Commands:  p <#> (preview top 20),  /term (filter),  ? (help)")

    visible = list(range(len(items)))

    def show_filtered():
        print("\n  Current list:")
        for i in visible:
            print("  " + items[i][2])

    while True:
        try:
            sel = input("Select> ").strip()
        except EOFError:
            sel = "canonical"

        if not sel:
            continue
        if sel == "?":
            print("Help: numbers, ranges, all, none, p <#> preview, /term filter")
            continue
        if sel.startswith("/"):
            term = sel[1:].lower()
            visible = [i for i in range(len(items)) if term in items[i][1].name.lower()]
            show_filtered()
            continue
        if sel.startswith("p "):
            try:
                nn = int(sel.split()[1])
                ii = nn - 1
                if 0 <= ii < len(items):
                    path = items[ii][1]
                    print(f"--- preview: {path}")
                    try:
                        with open(path, encoding="utf-8", errors="ignore") as f:
                            for i, line in enumerate(f):
                                if i >= 20:
                                    break
                                print("  " + line.rstrip())
                    except Exception as e:
                        print(f"  (preview error: {e})")
                else:
                    print("  invalid index")
            except Exception:
                print("  usage: p <number>")
            continue
        if sel.lower() in ("all", "a"):
            chosen = items
            break
        if sel.lower() in ("none", "n"):
            chosen = []
            break

        picks: Set[int] = set()
        ok = True
        for part in sel.split(","):
            part = part.strip()
            if not part:
                continue
            if "-" in part:
                try:
                    l, r = part.split("-", 1)
                    l = int(l)
                    r = int(r)
                    if l <= 0 or r <= 0 or l > len(items) or r > len(items) or l > r:
                        ok = False
                        break
                    for k in range(l, r + 1):
                        picks.add(k)
                except Exception:
                    ok = False
                    break
            else:
                try:
                    k = int(part)
                    if k <= 0 or k > len(items):
                        ok = False
                        break
                    picks.add(k)
                except Exception:
                    ok = False
                    break
        if not ok:
            print("  invalid selection")
            continue
        chosen = [items[k - 1] for k in sorted(picks)]
        break

    chosen_urls = [p for kind, p, _ in chosen if kind == "url"]
    chosen_hosts = [p for kind, p, _ in chosen if kind == "host"]
    return chosen_urls, chosen_hosts


@trace
def _noninteractive_select(domain: str, url_files: List[Path], host_files: List[Path], policy: str) -> Tuple[List[Path], List[Path]]:
    policy = policy.lower().strip()
    if policy == "all":
        return (sorted(url_files), sorted(host_files))
    if policy == "none":
        return ([], [])
    # canonical
    u: List[Path] = []
    for p in url_files:
        if p.name in CANONICAL_URL_FILES:
            u.append(p)
    h: List[Path] = []
    for p in host_files:
        if p.name in {"ct_domains.txt", "pdns_hostnames.txt"}:
            h.append(p)
    if not u:
        u = sorted(url_files)
    return (sorted(u), sorted(h))


@trace
def _build_auto_inputs_for_domain(
    domain: str,
    discovered: Dict[str, Dict[str, List[Path]]],
    allowed: Set[str],
    exclude_url_rules: Optional[list],
    outdir: Path,
    interactive: bool,
    noninteractive_policy: str,
    safe_paths: List[str]
) -> Optional[Path]:
    bucket = discovered.get(domain)
    if not bucket:
        return None
    url_files = bucket.get("url_files", [])
    host_files = bucket.get("host_files", [])
    if not url_files and not host_files:
        return None

    if interactive:
        chosen_urls, chosen_hosts = _prompt_picker(domain, url_files, host_files)
    else:
        chosen_urls, chosen_hosts = _noninteractive_select(domain, url_files, host_files, noninteractive_policy)

    if not chosen_urls and not chosen_hosts:
        log.info(f"[{domain}] no inputs selected.")
        return None

    inputs_dir = outdir / "inputs"
    inputs_dir.mkdir(parents=True, exist_ok=True)
    merged_path = inputs_dir / "merged_urls.txt"
    selection_path = inputs_dir / "selection.json"

    merged_set: Set[str] = set()
    for p in chosen_urls:
        for s in _read_lines(p):
            u = normalize_url_line(s)
            if u:
                merged_set.add(u)

    norm_paths: List[str] = []
    if chosen_hosts:
        raw_hosts: Set[str] = set()
        for hp in chosen_hosts:
            for s in _read_lines(hp):
                raw_hosts.add(s.strip())
        kept = _scope_intersect_hosts(raw_hosts, allowed)
        for sp in safe_paths:
            sp = sp.strip()
            if not sp:
                continue
            if not sp.startswith("/"):
                sp = "/" + sp
            norm_paths.append(sp)
        for h in kept:
            for sp in norm_paths:
                merged_set.add(f"https://{h}{sp}")

    with open(merged_path, "w", encoding="utf-8") as f:
        for u in sorted(merged_set):
            f.write(u + "\n")

    manifest = {
        "domain": domain,
        "selected_url_files": [str(p) for p in chosen_urls],
        "selected_host_files": [str(p) for p in chosen_hosts],
        "safe_paths": norm_paths,
        "total_urls": len(merged_set),
        "generated_at": datetime.now(timezone.utc).isoformat().replace("+00:00","Z"),
    }
    with open(selection_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    log.info(f"[{domain}] auto-discover built {merged_path} ({len(merged_set)} URLs)")
    return merged_path

# ---------------------------
# Rate-limit coordinator (per host)
# ---------------------------

class HostRateGate:
    def __init__(self):
        self._locks: Dict[str, asyncio.Lock] = {}
        self._next_ok: Dict[str, float] = {}
        self._global_lock = asyncio.Lock()

    @trace
    async def wait(self, host: str):
        async with self._global_lock:
            lock = self._locks.get(host)
            if lock is None:
                lock = asyncio.Lock()
                self._locks[host] = lock
        async with lock:
            now = time.monotonic()
            t = self._next_ok.get(host, 0.0)
            if t > now:
                delay = t - now
                log.info(f"RateGate: sleeping {delay:.2f}s for host={host}")
                await asyncio.sleep(delay)

    @trace
    async def push_back(self, host: str, sleep_s: float):
        if sleep_s <= 0:
            return
        async with self._global_lock:
            cur = self._next_ok.get(host, 0.0)
            newt = max(cur, time.monotonic()) + sleep_s
            self._next_ok[host] = newt
            log.debug(f"RateGate: next_ok[{host}] -> +{sleep_s:.2f}s")


@trace
def parse_retry_after(h: str) -> Optional[float]:
    if not h:
        return None
    h = h.strip()
    if re.fullmatch(r"\d+", h):
        try:
            return float(h)
        except Exception:
            return None
    try:
        dt = parsedate_to_datetime(h)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        diff = (dt - datetime.now(timezone.utc)).total_seconds()
        return max(0.0, diff)
    except Exception:
        return None


@trace
def parse_xrl_reset(h: str) -> Optional[float]:
    if not h:
        return None
    h = h.strip()
    if re.fullmatch(r"\d+", h):
        try:
            val = int(h)
            now = int(time.time())
            if val > now - 3600:
                return max(0.0, float(val - now))
            return max(0.0, float(val))
        except Exception:
            return None
    return None

# ---------------------------
# Downloader (direct-to-harvest)
# ---------------------------

@trace
async def download_url(
    session: aiohttp.ClientSession,
    sem: asyncio.Semaphore,
    url: str,
    harvest_dir: Path,
    user_agent: str,
    max_size: int,
    rps: float,
    timeout_s: int,
    max_retries: int,
    backoff_cap: int,
    respect_retry_after: bool,
    retry_after_cap: int,
    host_gate: HostRateGate,
    write_headers: bool,
    interesting_exts: Set[str],
    allowed_domains: Set[str],
    exclude_url_rules,
    max_redirects: int = 5,
) -> bool:
    def _host_ok(h: str) -> bool:
        if not h:
            return False
        h = h.strip().rstrip(".")
        if not h:
            return False
        if h.startswith(".") or ".." in h:
            return False
        try:
            h.encode("idna").decode("ascii")
        except Exception:
            return False
        return True

    async with sem:
        attempts = 0
        while attempts <= max_retries:
            attempts += 1

            cur_url = url
            redirects = 0

            while True:
                host = urllib.parse.urlparse(cur_url).hostname or ""
                if not _host_ok(host):
                    log.warning(
                        f"FAIL (non-retryable) url={url} err=invalid-host({host}) "
                        f"attempt={attempts}"
                    )
                    return False

                await asyncio.sleep(1.0 / max(0.01, rps))
                await host_gate.wait(host)
                t0 = time.perf_counter()

                try:
                    log.debug(f"GET start url={cur_url} attempt={attempts} redirects={redirects}")

                    async with session.get(
                        cur_url,
                        headers={"User-Agent": user_agent},
                        timeout=timeout_s,
                        allow_redirects=False,
                    ) as resp:

                        # Manual redirect handling (scope-guarded)
                        if resp.status in (301, 302, 303, 307, 308):
                            loc = resp.headers.get("Location", "") or ""
                            if not loc:
                                log.info(
                                    f"SKIP redirect(no-location) url={cur_url} status={resp.status} "
                                    f"elapsed_ms={int((time.perf_counter()-t0)*1000)} attempt={attempts}"
                                )
                                return False

                            if redirects >= max_redirects:
                                log.info(
                                    f"SKIP redirect(max) url={cur_url} status={resp.status} "
                                    f"elapsed_ms={int((time.perf_counter()-t0)*1000)} attempt={attempts}"
                                )
                                return False

                            # Resolve next URL (absolute)
                            base = str(resp.url) or cur_url
                            nxt = urllib.parse.urljoin(base, loc)

                            # Normalize + scope guard
                            nxt_norm = normalize_url_line(nxt) or ""
                            if not nxt_norm:
                                log.info(f"SKIP redirect(bad-url) url={cur_url} -> {nxt!r}")
                                return False

                            nxt_host = urllib.parse.urlparse(nxt_norm).hostname or ""
                            if not _host_ok(nxt_host):
                                log.info(f"SKIP redirect(invalid-host) url={cur_url} -> {nxt_norm}")
                                return False

                            if not in_scope(nxt_norm, allowed_domains):
                                log.info(f"SKIP off-scope redirect url={cur_url} -> {nxt_norm}")
                                return False

                            if excluded_by_url_rules(nxt_norm, exclude_url_rules):
                                log.info(f"SKIP redirect(excluded-by-rule) url={cur_url} -> {nxt_norm}")
                                return False

                            redirects += 1
                            cur_url = nxt_norm
                            continue  # follow redirect (still in-scope)

                        # Rate-limit handling on final response
                        if respect_retry_after and resp.status in (429, 503):
                            ra = parse_retry_after(resp.headers.get("Retry-After", ""))
                            xrl = parse_xrl_reset(resp.headers.get("X-RateLimit-Reset", ""))
                            wait_s = ra if ra is not None else xrl
                            if wait_s is not None:
                                wait_s = min(max(0.0, wait_s), float(retry_after_cap)) + random.random()
                                log.warning(f"Rate limited: status={resp.status} url={cur_url} waiting {wait_s:.2f}s")
                                await host_gate.push_back(host, wait_s)
                                if attempts > max_retries:
                                    return False
                                await asyncio.sleep(wait_s)
                                break  # retry outer attempt loop

                        headers = "".join(f"{k}: {v}\n" for k, v in resp.headers.items())
                        ext = guess_ext_from_headers(headers)
                        if ext == ".txt":
                            ext = guess_ext_from_url(str(resp.url) or cur_url)

                        # If still .txt but URL suffix is interesting, use it
                        if ext == ".txt":
                            try:
                                path_ext = os.path.splitext(urllib.parse.urlparse(str(resp.url) or cur_url).path)[1].lower()
                                if path_ext in interesting_exts:
                                    ext = path_ext
                            except Exception:
                                pass

                        if ext not in interesting_exts:
                            log.info(f"SKIP uninteresting type ext={ext} url={cur_url} status={resp.status} attempt={attempts}")
                            return False

                        body = await resp.read()
                        if len(body) > max_size:
                            log.info(
                                f"SKIP size>{max_size} url={cur_url} status={resp.status} len={len(body)} "
                                f"elapsed_ms={int((time.perf_counter()-t0)*1000)} attempt={attempts}"
                            )
                            if write_headers:
                                fname = safe_filename(str(resp.url) or cur_url)
                                hdr_path = Path(harvest_dir) / f"{fname}.hdr"
                                async with aiofiles.open(hdr_path, "w") as f:
                                    await f.write(headers + f"NOTE: skipped due to size>{max_size}\n")
                            return False

                        final_url = str(resp.url) or cur_url
                        fname = safe_filename(final_url)
                        body_path = Path(harvest_dir) / f"{fname}{ext}"

                        # Sidecar URL
                        url_path = Path(harvest_dir) / f"{fname}.url"
                        async with aiofiles.open(url_path, "w") as f:
                            await f.write(final_url)

                        if write_headers:
                            hdr_path = Path(harvest_dir) / f"{fname}.hdr"
                            async with aiofiles.open(hdr_path, "w") as f:
                                await f.write(headers)

                        async with aiofiles.open(body_path, "wb") as f:
                            await f.write(body)

                        log.info(
                            f"OK url={url} status={resp.status} len={len(body)} ext={ext} "
                            f"elapsed_ms={int((time.perf_counter()-t0)*1000)} attempt={attempts} -> {body_path.name}"
                        )
                        return True

                except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                    if attempts > max_retries:
                        log.warning(
                            f"FAIL (no retries left) url={url} err={e} "
                            f"elapsed_ms={int((time.perf_counter()-t0)*1000)} attempt={attempts}"
                        )
                        return False
                    sleep_s = min(2 ** attempts, backoff_cap) + random.random()
                    log.warning(
                        f"Transient error url={url} err={e} attempt={attempts}/{max_retries} "
                        f"backing off {sleep_s:.2f}s"
                    )
                    await asyncio.sleep(sleep_s)
                    break  # retry outer attempt loop

                except Exception as e:
                    log.warning(
                        f"FAIL (non-retryable) url={url} err={e} "
                        f"elapsed_ms={int((time.perf_counter()-t0)*1000)} attempt={attempts}"
                    )
                    return False

        return False

# ---------------------------
# URL analysis (pre-harvest) - writes <out>/analysis/*
# ---------------------------

JUICY_PATHS_RE = re.compile(
    r"/(?:login|admin|wp-login|wp-admin|register|api|wp-json|xmlrpc|uploads|backup|.env|phpmyadmin)(?:/|$)",
    re.IGNORECASE
)
SECRETS_RE = re.compile(r"(api[_-]?key|token|secret|password|auth)[=:/]", re.IGNORECASE)


@trace
def _url_has_params(u: str) -> bool:
    return "?" in u


@trace
def _extract_param_keys_python(urls: List[str]) -> List[str]:
    keys: Set[str] = set()
    for u in urls:
        try:
            q = urllib.parse.urlsplit(u).query
            for k, _ in urllib.parse.parse_qsl(q, keep_blank_values=True):
                if k:
                    keys.add(k)
        except Exception:
            continue
    return sorted(keys)


@trace
def url_analysis(urls: List[str], outdir: Path, gf_dir: Optional[str], unfurl_bin: Optional[str], httpx_bin: Optional[str]):
    ana_dir = outdir / "analysis"
    ana_dir.mkdir(parents=True, exist_ok=True)

    urls_file = ana_dir / "urls_all.txt"
    with open(urls_file, "w", encoding="utf-8") as f:
        for u in urls:
            f.write(u + "\n")

    # NEW: unique .js URLs (archived providers, post-scope/robots)
    try:
        js_urls = set()
        for u in urls:
            try:
                p = urllib.parse.urlsplit(u).path.lower()
            except Exception:
                continue
            if p.endswith(".js"):
                js_urls.add(u)
        (ana_dir / "jsfile_links.txt").write_text(
            "\n".join(sorted(js_urls)) + ("\n" if js_urls else ""),
            encoding="utf-8"
        )
        log.info(f"jsfile_links.txt written: {len(js_urls)} URLs")
    except Exception as e:
        log.warning(f"Failed to write jsfile_links.txt: {e}")

    # Juicy paths
    juicy = sorted({u for u in urls if JUICY_PATHS_RE.search(urllib.parse.urlsplit(u).path or "")})
    (ana_dir / "interesting.txt").write_text("\n".join(juicy) + ("\n" if juicy else ""), encoding="utf-8")

    # URLs with params
    with_params = sorted({u for u in urls if _url_has_params(u)})
    (ana_dir / "urls_with_params.txt").write_text("\n".join(with_params) + ("\n" if with_params else ""), encoding="utf-8")

    # Unique param keys (prefer unfurl if available)
    keys_out = ana_dir / "unique_parameters.txt"
    if unfurl_bin and shutil.which(unfurl_bin):
        try:
            cp = subprocess.run(
                [unfurl_bin, "keys"],
                input="\n".join(with_params),
                text=True, capture_output=True, check=False
            )
            lines = sorted({s.strip() for s in cp.stdout.splitlines() if s.strip()})
            keys_out.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
        except Exception as e:
            log.warning(f"unfurl failed: {e}; falling back to python parser")
            lines = _extract_param_keys_python(with_params)
            keys_out.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
    else:
        lines = _extract_param_keys_python(with_params)
        keys_out.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

    # Potential secrets in URLs
    secrets = sorted({u for u in urls if SECRETS_RE.search(u)})
    (ana_dir / "potential_secrets.txt").write_text("\n".join(secrets) + ("\n" if secrets else ""), encoding="utf-8")

    # GF on URLs (xss/ssrf/sqli) if gf + patterns dir present
    if gf_dir and shutil.which("gf"):
        for patt in ("xss", "ssrf", "sqli"):
            outp = ana_dir / f"{patt}_candidates.txt"
            try:
                cp = subprocess.run(
                    ["gf", patt],  # use pattern name
                    input="\n".join(urls),
                    text=True, capture_output=True, check=False
                )
                if cp.returncode != 0 and cp.stderr:
                    log.warning(f"gf({patt}) rc={cp.returncode} err={cp.stderr.strip()[:300]}")
                lines = sorted({s.strip() for s in cp.stdout.splitlines() if s.strip()})
                outp.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")
            except Exception as e:
                log.warning(f"gf {patt} failed: {e}")

# ---------------------------
# Sourcemap helpers & pipeline
# ---------------------------

@trace
def _extract_inline_map(js_bytes: bytes) -> Optional[bytes]:
    tail = js_bytes[-8192:]
    head = js_bytes[:4096]
    for chunk in (tail, head):
        m = re.search(
            rb"sourceMappingURL\s*=\s*data:application/json(?:;charset=[^;,\s]+)?;base64,([A-Za-z0-9+/=]+)",
            chunk,
            flags=re.IGNORECASE,
        )
        if m:
            try:
                return base64.b64decode(m.group(1), validate=True)
            except Exception:
                continue
    return None


@trace
def _extract_comment_url(js_bytes: bytes) -> Optional[str]:
    for chunk in (js_bytes[-8192:], js_bytes[:4096]):
        m = SM_COMMENT_RE.search(chunk.decode(errors="ignore"))
        if m:
            return m.group("url").strip()
    return None


@trace
def _heuristic_candidates(js_url: str) -> List[str]:
    parsed = urllib.parse.urlparse(js_url)
    path = parsed.path or ""
    cands = set()
    cands.add(urllib.parse.urlunparse(parsed._replace(path=path, query=parsed.query)) + ".map")
    if path.endswith(".js"):
        cands.add(urllib.parse.urlunparse(parsed._replace(path=path + ".map")))
    if path.endswith(".min.js"):
        cands.add(urllib.parse.urlunparse(parsed._replace(path=path + ".map")))
    return list(cands)


@trace
async def _head_url(session: aiohttp.ClientSession, url: str, user_agent: str, timeout_s: int) -> Optional[aiohttp.ClientResponse]:
    try:
        return await session.head(url, headers={"User-Agent": user_agent}, timeout=timeout_s, allow_redirects=True)
    except Exception as e:
        log.debug(f"HEAD fail {url}: {e}")
        return None


@trace
def _valid_map_json(b: bytes) -> Tuple[bool, Optional[dict]]:
    try:
        j = json.loads(b.decode("utf-8", errors="ignore"))
    except Exception:
        return (False, None)
    if not isinstance(j, dict):
        return (False, None)
    if "mappings" in j and ("version" in j or "sources" in j):
        return (True, j)
    return (False, j)


@trace
async def discover_and_fetch_maps(
    session: aiohttp.ClientSession,
    sem: asyncio.Semaphore,
    host_gate: HostRateGate,
    harvest_dir: Path,
    allowed_domains: Set[str],
    user_agent: str,
    respect_retry_after: bool,
    retry_after_cap: int,
    rps: float,
    head_timeout: int,
    map_timeout: int,
    map_retries: int,
    backoff_cap: int,
    max_map_size: int,
    respect_robots_flag: bool,
    extract_sources: bool,
    chase_sources: bool,
    map_sources_dir: Path,
) -> Tuple[int, int]:
    js_files = sorted(p for p in harvest_dir.glob("*.js") if p.is_file())
    saved = 0
    scanned = 0

    @trace
    async def fetch_map(map_url: str, out_path: Path, meta_path: Path, ref_js_url: str, discovery: str) -> bool:
        if not in_scope(map_url, allowed_domains):
            log.debug(f"map out-of-scope: {map_url}")
            return False
        if respect_robots_flag:
            if not await allowed_by_robots(map_url, user_agent, respect=True):
                log.debug(f"robots disallow map: {map_url}")
                return False

        host = urllib.parse.urlparse(map_url).hostname or ""
        attempts = 0
        while attempts <= map_retries:
            attempts += 1
            await asyncio.sleep(1.0 / max(0.01, rps))
            await host_gate.wait(host)
            t0 = time.perf_counter()
            try:
                async with session.get(map_url, headers={"User-Agent": user_agent}, timeout=map_timeout) as resp:
                    if respect_retry_after and resp.status in (429, 503):
                        ra = parse_retry_after(resp.headers.get("Retry-After", ""))
                        xrl = parse_xrl_reset(resp.headers.get("X-RateLimit-Reset", ""))
                        wait_s = ra if ra is not None else xrl
                        if wait_s is not None:
                            wait_s = min(max(0.0, wait_s), float(retry_after_cap)) + random.random()
                            log.warning(f"MAP rate limited: {map_url} wait {wait_s:.2f}s")
                            await host_gate.push_back(host, wait_s)
                            if attempts > map_retries:
                                return False
                            await asyncio.sleep(wait_s)
                            continue

                    cl = resp.headers.get("Content-Length")
                    if cl and cl.isdigit() and int(cl) > max_map_size:
                        log.info(f"MAP too large (Content-Length): {map_url} > {max_map_size}")
                        return False

                    data = await resp.read()
                    if len(data) > max_map_size:
                        log.info(f"MAP too large (read): {map_url} > {max_map_size}")
                        return False

                    ok, j = _valid_map_json(data)
                    if not ok:
                        log.info(f"MAP invalid JSON-ish: {map_url}")
                        return False

                    async with aiofiles.open(out_path, "wb") as f:
                        await f.write(data)

                    meta = {
                        "js_url": ref_js_url,
                        "map_url": str(resp.url),
                        "discovery": discovery,
                        "status": resp.status,
                        "size": len(data),
                        "fetched_at": utc_now_iso(),
                    }
                    async with aiofiles.open(meta_path, "w") as f:
                        await f.write(json.dumps(meta, indent=2))
                    log.info(f"MAP OK {discovery}: {map_url} -> {out_path.name} ({len(data)} bytes)")
                    return True

            except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                if attempts > map_retries:
                    log.warning(f"MAP FAIL (no retries left): {map_url} err={e}")
                    return False
                sleep_s = min(2 ** attempts, backoff_cap) + random.random()
                log.warning(f"MAP transient error: {map_url} attempt={attempts}/{map_retries} backoff {sleep_s:.2f}s")
                await asyncio.sleep(sleep_s)
            except Exception as e:
                log.warning(f"MAP FAIL (non-retryable): {map_url} err={e}")
                return False
        return False

    @trace
    async def _maybe_extract_or_chase(map_path: Path, js_url: str):
        """
        Write sources_manifest.json and, if chase_sources=True, fetch each source URL
        (scope/robots/Retry-After aware) into map_sources_dir/<js-stem>/.
        """
        try:
            async with aiofiles.open(map_path, "rb") as f:
                b = await f.read()
            ok, j = _valid_map_json(b)
            if not ok or not isinstance(j, dict):
                return

            # Prepare output folder per JS file
            js_stem = map_path.stem.replace(".js", "")
            out_folder = map_sources_dir / js_stem
            out_folder.mkdir(parents=True, exist_ok=True)

            # Always write a manifest of sources we saw in the map
            sources: List[str] = j.get("sources") or []
            manifest_path = out_folder / "sources_manifest.json"
            src_manifest = {
                "js_url": js_url,
                "sources": sources,
                "saved_at": utc_now_iso(),
            }
            async with aiofiles.open(manifest_path, "w") as mf:
                await mf.write(json.dumps(src_manifest, indent=2))

            if not (chase_sources and sources):
                return  # only manifest requested, or nothing to chase

            # When chasing, keep it conservative
            source_max_size = min(max_map_size, 2 * 1024 * 1024)
            base = js_url if js_url else ""
            base_dir = urllib.parse.urljoin(base, ".") if base else None

            async def fetch_source(src: str) -> Optional[Path]:
                # Build absolute URL
                if "://" in src:
                    src_url = src
                else:
                    if not base_dir:
                        return None
                    src_url = urllib.parse.urljoin(base_dir, src)

                # Scope & robots
                if not in_scope(src_url, allowed_domains):
                    log.debug(f"map-source out-of-scope: {src_url}")
                    return None
                if respect_robots_flag:
                    if not await allowed_by_robots(src_url, user_agent, respect=True):
                        log.debug(f"robots disallow map-source: {src_url}")
                        return None

                # Per-host throttling + retry logic
                host = urllib.parse.urlparse(src_url).hostname or ""
                attempts = 0
                while attempts <= map_retries:
                    attempts += 1
                    await asyncio.sleep(1.0 / max(0.01, rps))
                    await host_gate.wait(host)
                    try:
                        async with session.get(src_url, headers={"User-Agent": user_agent}, timeout=map_timeout) as r:
                            if respect_retry_after and r.status in (429, 503):
                                ra = parse_retry_after(r.headers.get("Retry-After", ""))
                                xrl = parse_xrl_reset(r.headers.get("X-RateLimit-Reset", ""))
                                wait_s = ra if ra is not None else xrl
                                if wait_s is not None:
                                    wait_s = min(max(0.0, wait_s), float(retry_after_cap)) + random.random()
                                    log.warning(f"MAP-SRC rate limited: {src_url} wait {wait_s:.2f}s")
                                    await host_gate.push_back(host, wait_s)
                                    if attempts > map_retries:
                                        return None
                                    await asyncio.sleep(wait_s)
                                    continue

                            cl = r.headers.get("Content-Length")
                            if cl and cl.isdigit() and int(cl) > source_max_size:
                                log.debug(f"MAP-SRC too large by header: {src_url}")
                                return None
                            data = await r.read()
                            if len(data) > source_max_size:
                                log.debug(f"MAP-SRC too large by body: {src_url}")
                                return None

                            fname = re.sub(r"[^A-Za-z0-9._-]", "_", Path(src).name) or "source"
                            out_name = f"{abs(hash(src_url)) % (10**12)}_{fname}"
                            out_path = out_folder / out_name
                            async with aiofiles.open(out_path, "wb") as fo:
                                await fo.write(data)

                            meta = {
                                "src_url": str(r.url),
                                "status": r.status,
                                "size": len(data),
                                "fetched_at": utc_now_iso(),
                            }
                            async with aiofiles.open(out_path.with_suffix(out_path.suffix + ".meta.json"), "w") as mo:
                                await mo.write(json.dumps(meta, indent=2))

                            log.info(f"MAP-SRC OK {src_url} -> {out_path.name} ({len(data)} bytes)")
                            return out_path

                    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
                        if attempts > map_retries:
                            if len(str(e)) < 400:
                                log.debug(f"MAP-SRC fail(no retries): {src_url} err={e}")
                            else:
                                log.debug(f"MAP-SRC fail(no retries): {src_url}")
                            return None
                        sleep_s = min(2 ** attempts, backoff_cap) + random.random()
                        log.debug(f"MAP-SRC transient: {src_url} attempt={attempts}/{map_retries} backoff {sleep_s:.2f}s")
                        await asyncio.sleep(sleep_s)
                    except Exception as e:
                        if len(str(e)) < 400:
                            log.debug(f"MAP-SRC fail(non-retryable): {src_url} err={e}")
                        else:
                            log.debug(f"MAP-SRC fail(non-retryable): {src_url}")
                        return None

                return None

            for s in sources:
                try:
                    await fetch_source(s)
                except Exception:
                    continue
        except Exception as e:
            log.debug(f"_maybe_extract_or_chase error: {e}")

    # Walk harvested JS files, discover + fetch maps, then optionally extract/chase sources
    for js_path in js_files:
        scanned += 1
        stem = js_path.with_suffix("")
        map_path = Path(str(stem) + ".js.map")
        meta_path = Path(str(stem) + ".map.meta.json")

        # If a map already exists next to the JS, just process sources and continue
        if map_path.exists():
            try:
                js_final_url = ""
                url_sidecar = Path(str(stem) + ".url")
                if url_sidecar.exists():
                    js_final_url = url_sidecar.read_text(errors="ignore").strip()
            except Exception:
                js_final_url = ""
            await _maybe_extract_or_chase(map_path, js_final_url)
            continue

        # Load JS & discover candidate map URLs
        try:
            async with aiofiles.open(js_path, "rb") as f:
                content = await f.read()
        except Exception:
            continue

        # Try to resolve the final JS URL from its sidecar
        js_final_url = ""
        url_sidecar = Path(str(stem) + ".url")
        if url_sidecar.exists():
            try:
                js_final_url = url_sidecar.read_text(errors="ignore").strip()
            except Exception:
                js_final_url = ""

        # 1) Inline data: URL in JS
        inline = _extract_inline_map(content)
        if inline is not None:
            ok, _ = _valid_map_json(inline)
            if ok:
                async with aiofiles.open(map_path, "wb") as f:
                    await f.write(inline)
                meta = {
                    "js_url": js_final_url or "",
                    "map_url": "data:application/json;base64,...",
                    "discovery": "inline",
                    "status": 200,
                    "size": len(inline),
                    "fetched_at": utc_now_iso(),
                }
                async with aiofiles.open(meta_path, "w") as f:
                    await f.write(json.dumps(meta, indent=2))
                log.info(f"MAP OK inline -> {map_path.name} ({len(inline)} bytes)")
                saved += 1
                await _maybe_extract_or_chase(map_path, js_final_url or "")
                continue

        # 2) SourceMap header via HEAD on the JS
        header_map_url = None
        if js_final_url:
            try:
                async with aiohttp.ClientSession() as head_sess:
                    h = await _head_url(head_sess, js_final_url, user_agent, head_timeout)
                    if h and h.status < 400:
                        header_map_url = h.headers.get("SourceMap") or h.headers.get("X-SourceMap")
                        if header_map_url:
                            header_map_url = urllib.parse.urljoin(js_final_url, header_map_url.strip())
            except Exception:
                header_map_url = None

        # 3) //@ sourceMappingURL comment in JS
        comment_url = _extract_comment_url(content)

        # 4) Heuristics based on JS URL
        candidate_urls: List[Tuple[str, str]] = []
        if header_map_url:
            candidate_urls.append((header_map_url, "header"))
        if comment_url:
            resolved = urllib.parse.urljoin(js_final_url, comment_url) if js_final_url else comment_url
            candidate_urls.append((resolved, "comment"))
        if js_final_url:
            for cu in _heuristic_candidates(js_final_url):
                candidate_urls.append((cu, "heuristic"))

        # Dedup + quick HEAD filter to enforce size before GET
        seen = set()
        normed: List[Tuple[str, str]] = []
        for cu, how in candidate_urls:
            try:
                u = urllib.parse.urlsplit(cu)
                cu_norm = urllib.parse.urlunsplit(u._replace(fragment=""))
            except Exception:
                cu_norm = cu
            if cu_norm in seen:
                continue
            seen.add(cu_norm)
            normed.append((cu_norm, how))

        viable: List[Tuple[str, str]] = []
        async with aiohttp.ClientSession() as head_sess:
            for cu, how in normed:
                try:
                    h = await _head_url(head_sess, cu, user_agent, head_timeout)
                    if not h or h.status >= 400:
                        continue
                    cl = h.headers.get("Content-Length")
                    if cl and cl.isdigit() and int(cl) > max_map_size:
                        continue
                    viable.append((cu, how))
                except Exception:
                    continue

        # Try to fetch maps in order until one succeeds
        fetched = False
        for cu, how in viable:
            ok = await fetch_map(
                cu, map_path, meta_path,
                ref_js_url=js_final_url or "",
                discovery=how
            )
            if ok:
                saved += 1
                fetched = True
                await _maybe_extract_or_chase(map_path, js_final_url or "")
                break

        if not fetched and (header_map_url or comment_url or js_final_url):
            log.debug(f"No valid sourcemap fetched for {js_path.name}")

    # IMPORTANT: return a tuple so the caller can unpack it
    return (saved, scanned)

# ---------------------------
# VENV utilities
# ---------------------------

@trace
def venv_python_path(venv_dir: Path) -> Path:
    if platform.system().lower().startswith("win"):
        return venv_dir / "Scripts" / "python.exe"
    return venv_dir / "bin" / "python"


@trace
def ensure_venv(venv_dir: Path, create: bool) -> Path:
    if venv_dir.exists():
        py = venv_python_path(venv_dir)
        if py.exists():
            log.info(f"Using existing venv @ {venv_dir}")
            return py
        raise RuntimeError(f"Existing venv missing python: {py}")
    if not create:
        raise RuntimeError(f"Venv not found: {venv_dir}. Pass --venv-create to create it.")
    log.info(f"Creating venv @ {venv_dir}")
    subprocess.run([sys.executable, "-m", "venv", str(venv_dir)], check=True)
    py = venv_python_path(venv_dir)
    if not py.exists():
        raise RuntimeError(f"Venv created but python missing at {py}")
    subprocess.run([str(py), "-m", "pip", "install", "-U", "pip", "wheel"], check=False)
    return py


@trace
def pip_install_requirements(py_exec, req_file, cwd=None, extra_args=None):
    cmd = [py_exec, "-m", "pip", "install", "-r", str(req_file)]
    if extra_args:
        cmd.extend(extra_args)

    log.info("Installing UCA requirements from %s", req_file)

    # Ensure venv tools (semgrep, etc.) are discoverable even if the venv isn't activated.
    env = os.environ.copy()
    try:
        venv_bin = str(Path(py_exec).resolve().parent)
        env["PATH"] = venv_bin + os.pathsep + env.get("PATH", "")
    except Exception:
        pass

    subprocess.run(cmd, cwd=str(cwd) if cwd else None, env=env, check=False)
def pip_install_packages(
    py_exec: Path,
    packages: List[str],
    wheels_dir: Optional[Path] = None,
    extra_index: Optional[str] = None
) -> None:
    if not packages:
        return
    cmd = [str(py_exec), "-m", "pip", "install", *packages]
    if wheels_dir and wheels_dir.exists():
        cmd += ["--no-index", "--find-links", str(wheels_dir)]
    if extra_index:
        cmd += ["--extra-index-url", extra_index]
    log.info(f"Installing packages into venv: {', '.join(packages)}")
    subprocess.run(cmd, check=False)

# ---------------------------
# GF patterns (optional)
# ---------------------------

@trace
def run_gf(
    harvest_dir: Path,
    gf_patterns_dir: Optional[str],
    outdir: Path,
    max_bytes: int = 500_000,  # tighter cap for secrets hunting
    per_call_timeout: int = 8,  # a bit stricter
    scan_html: bool = False,  # still off by default
    include_patterns: Optional[List[str]] = None,  # NEW allowlist
) -> None:
    os.makedirs(outdir, exist_ok=True)
    gf_path = shutil.which("gf")
    if not gf_path:
        log.warning("gf not installed, skipping.")
        return

    env = os.environ.copy()
    # Honor $GF_PATTERNS_DIR if provided, else use --gf-patterns
    if gf_patterns_dir:
        if Path(gf_patterns_dir).exists():
            env["GF_PATTERNS_DIR"] = str(Path(gf_patterns_dir).resolve())
        else:
            log.warning(f"gf patterns dir not found: {gf_patterns_dir}")

    # Discover patterns
    try:
        cp_list = subprocess.run([gf_path, "-list"], text=True, capture_output=True, check=False, env=env)
        all_patterns = [s.strip() for s in cp_list.stdout.splitlines() if s.strip()]
    except Exception as e:
        log.warning(f"gf -list failed: {e}")
        all_patterns = []

    if not all_patterns:
        patt_dir = Path(env.get("GF_PATTERNS_DIR", Path.home() / ".gf"))
        all_patterns = [p.stem for p in patt_dir.glob("*.json")]

    # Apply allowlist if passed; else use common secrets first
    default_hot = [
        "aws-keys_secrets", "google-keys_secrets", "github_secrets", "slack-webhook_secrets",
        "stripe-keys_secrets", "twilio-keys_secrets", "google-token_secrets",
        "facebook-token_secrets", "facebook-oauth_secrets", "twitter-token_secrets",
    ]
    if include_patterns:
        content_patterns = [p for p in include_patterns if p in all_patterns]
    else:
        content_patterns = [p for p in default_hot if p in all_patterns]
        if not content_patterns:
            # fallback to any *_secrets to avoid scanning everything
            content_patterns = [p for p in all_patterns if p.endswith("_secrets") or "secret" in p.lower()]

    # Targets (skip HTML/CSS unless scan_html=True)
    TEXT_EXTS = {
        ".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte",
        ".json", ".json5", ".map", ".txt",
        ".toml", ".yml", ".yaml", ".properties", ".conf", ".config",
    }
    HTML_EXTS = {".html", ".xhtml"}

    # Simple HTML extractor
    href_re = re.compile(r'''(?i)\b(?:href|src|action)\s*=\s*["']([^"']{1,4096})["']''')
    script_re = re.compile(r'(?is)<script[^>]*>(.*?)</script>')

    def extract_from_html(text: str) -> str:
        out: List[str] = []
        for m in href_re.finditer(text):
            out.append(m.group(1))
        for m in script_re.finditer(text):
            block = m.group(1)
            if len(block) > 200_000:
                block = block[:200_000]
            out.append(block)
        return "\n".join(out)

    # Seed prefilter (cheap contains)
    SEEDS = (
        "AKIA", "ASIA",  # AWS
        "AIza",  # Google API
        "ghp_", "gho_", "ghs_",  # GitHub tokens
        "xoxb-", "xoxp-", "xoxa-",  # Slack
        "sk_live_", "sk_test_",  # Stripe
        "EAAC", "EAAE",  # Facebook tokens (short prefixes)
        "twilio", "AC",  # Twilio
        "eyJhbGciOi",  # JWT-ish base64 header
    )

    # Long-line chunker (break mega-lines)
    def soften_minified(s: str, width: int = 4000) -> str:
        if "\n" in s and max((len(line) for line in s.splitlines()), default=0) < width:
            return s  # looks fine
        # Insert \n after common delimiters and hard-wrap very long runs
        s = re.sub(r'([;{}\],])', r'\1\n', s)
        out_chunks: List[str] = []
        line = 0
        while line < len(s):
            out_chunks.append(s[line:line + width])
            line += width
        return "\n".join(out_chunks)

    # Collect candidate files
    files: List[Path] = []
    for p in harvest_dir.rglob("*"):
        try:
            if not p.is_file():
                continue
            sz = p.stat().st_size
            if sz == 0 or sz > max_bytes:
                continue
            ext = p.suffix.lower()
            if ext in TEXT_EXTS:
                files.append(p)
            elif scan_html and ext in HTML_EXTS:
                files.append(p)
        except FileNotFoundError:
            continue

    total_files = len(files)
    log.info(f"gf: scanning {total_files} files with {len(content_patterns)} patterns (timeout {per_call_timeout}s)")

    # Prepare outputs
    outs = {}
    try:
        for pat in content_patterns:
            outp = outdir / f"{pat}.matches"
            outs[pat] = open(outp, "a", encoding="utf-8")
    except Exception as e:
        log.warning(f"opening outputs failed: {e}")
        for fh in outs.values():
            try:
                fh.close()
            except Exception:
                pass
        return

    t0 = time.time()
    try:
        for i, f in enumerate(files, 1):
            if i == 1 or i % 10 == 0 or i == total_files:
                rate = i / max(0.001, (time.time() - t0))
                log.info(f"gf: {i}/{total_files} files ~{rate:.1f} f/s, ETA {int((total_files-i)/rate) if rate>0 else 0}s")

            try:
                raw = f.read_text(encoding="utf-8", errors="ignore")
            except Exception:
                continue
            if not raw:
                continue

            ext = f.suffix.lower()
            data = extract_from_html(raw) if (scan_html and ext in HTML_EXTS) else raw

            # Seed gate: skip if no cheap indicator present
            if not any(seed in data for seed in SEEDS):
                continue

            # Soften minified/one-line blobs
            data = soften_minified(data)

            rel = str(f.relative_to(harvest_dir))
            for pat in content_patterns:
                try:
                    cp = subprocess.run(
                        [gf_path, pat],
                        input=data,
                        text=True,
                        capture_output=True,
                        timeout=per_call_timeout,
                        check=False,
                        env=env,
                    )
                except subprocess.TimeoutExpired:
                    log.debug(f"gf({pat}) timeout on {rel} after {per_call_timeout}s")
                    continue
                except Exception as e:
                    log.debug(f"gf({pat}) on {rel} error: {e}")
                    continue

                if cp.stdout:
                    for line in cp.stdout.splitlines():
                        s = line.strip()
                        if s:
                            try:
                                outs[pat].write(f"{rel} :: {s}\n")
                            except Exception:
                                pass

            if i % 20 == 0:
                for fh in outs.values():
                    try:
                        fh.flush()
                    except Exception:
                        pass
    finally:
        for fh in outs.values():
            try:
                fh.close()
            except Exception:
                pass

# ---------------------------
# Curate ONLY interesting files for UCA
# ---------------------------

@trace
def build_uca_source(
    harvest_dir: Path, uca_src_dir: Path, allowed_exts: List[str],
    include_maps: bool, link_mode: str = "symlink"
) -> int:
    if uca_src_dir.exists():
        shutil.rmtree(uca_src_dir)
    uca_src_dir.mkdir(parents=True, exist_ok=True)

    allowed = {e.lower().strip() for e in allowed_exts if e.strip().startswith(".")}
    if include_maps:
        allowed.add(".map")

    count = 0
    for p in harvest_dir.iterdir():
        if not p.is_file():
            continue
        ext = p.suffix.lower()
        if ext in allowed:
            dst = uca_src_dir / p.name
            try:
                if link_mode == "symlink":
                    os.symlink(p.resolve(), dst)
                else:
                    shutil.copy2(p, dst)
            except (OSError, NotImplementedError):
                shutil.copy2(p, dst)
            count += 1
    log.info(f"UCA source curated: {count} files -> {uca_src_dir} (exts={','.join(sorted(allowed))})")
    return count

# ---------------------------
# Run UCA (venv + auto-heal missing deps) with LIVE streaming
# ---------------------------

@trace
def run_uca(
    uca_src_dir: Path,
    outdir: Path,
    custom_patterns: Optional[str],
    ignore_file: Optional[str],
    venv_py: Optional[Path] = None,
    auto_install_missing: bool = True,
    wheels_dir: Optional[Path] = None,
    extra_index: Optional[str] = None,
    uca_format: str = "html",
    uca_enable_semgrep: bool = False,
    uca_enable_debug_log: bool = False,
    uca_scan_all_text: bool = True,
):
    import threading
    from queue import Queue, Empty

    analyzer = Path("code_analyzer.pyz")
    if not analyzer.exists():
        # fallback: look next to this script (tool bundle layout)
        analyzer = Path(__file__).resolve().with_name("code_analyzer.pyz")

    if not analyzer.exists():
        log.warning("code_analyzer.pyz not found (CWD or tools dir); skipping UCA")
        return

    python_exec = str(venv_py) if venv_py else shutil.which("python3") or sys.executable

    burp_json = outdir / "burp_export.json"
    findings_json = outdir / "findings.json"

    base_cmd = [
        python_exec, str(analyzer),
        "-o", str(outdir),
        "-f", uca_format,
        "--export-for-burp", str(burp_json),
        "--dump-findings", str(findings_json),
    ]
    if uca_scan_all_text:
        base_cmd.append("--scan-all-text")
    if uca_enable_semgrep:
        base_cmd.append("--enable-semgrep")
    if uca_enable_debug_log:
        base_cmd.append("--enable-debug-log")
    if custom_patterns:
        base_cmd.extend(["--custom-patterns", str(custom_patterns)])
    if ignore_file:
        base_cmd.extend(["--ignore", str(ignore_file)])
    base_cmd.append(str(uca_src_dir))

    def _stream_process(cmd) -> Tuple[int, str]:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )

        q: Queue = Queue()
        combined_chunks: List[str] = []

        def _reader(stream, tag: str):
            for line in stream:
                msg = line.rstrip("\n")
                if tag == "STDOUT":
                    log.info(f"UCA | {msg}")
                else:
                    log.debug(f"UCA! {msg}")
                combined_chunks.append(msg + "\n")
                q.put(None)
            q.put(None)

        t_out = threading.Thread(target=_reader, args=(proc.stdout, "STDOUT"), daemon=True)
        t_err = threading.Thread(target=_reader, args=(proc.stderr, "STDERR"), daemon=True)
        t_out.start(); t_err.start()

        while True:
            rc = proc.poll()
            try:
                _ = q.get(timeout=0.1)
            except Empty:
                pass
            if rc is not None and not t_out.is_alive() and not t_err.is_alive():
                break

        return rc, "".join(combined_chunks)

    max_attempts = 5 if auto_install_missing and venv_py else 1
    for attempt in range(1, max_attempts + 1):
        cmd = list(base_cmd)
        log.info(f"UCA start (attempt {attempt}/{max_attempts}) cmd={' '.join(cmd)} (python={python_exec})")
        rc, out = _stream_process(cmd)

        if rc == 0:
            log.info(f"UCA done. Output: {outdir}")
            return

        log.warning(f"UCA failed (rc={rc})")

        if not (auto_install_missing and venv_py):
            log.error("Not auto-installing missing deps (disabled or no venv).")
            return

        m = re.search(r"ModuleNotFoundError:\s*No module named ['\"]([^'\"]+)['\"]", out)
        if not m:
            log.error("Failure not caused by missing module; not retrying.")
            return

        missing = m.group(1)
        pkg = missing.split(".")[0]
        log.info(f"Detected missing module: {missing} -> installing '{pkg}' in venv and retrying.")
        pip_install_packages(venv_py, [pkg],
                             wheels_dir=Path(wheels_dir) if wheels_dir else None,
                             extra_index=extra_index)
    log.error("UCA failed after auto-install retries.")

# ---------------------------
# NEW: Post-harvest live analysis & optional JS tooling (skeleton)
# ---------------------------

@trace
def _build_live_urls_list(harvest_dir: Path, out_file: Path) -> int:
    urls: Set[str] = set()
    for p in harvest_dir.glob("*.url"):
        try:
            u = p.read_text(errors="ignore").strip()
            if u:
                urls.add(u)
        except Exception:
            continue
    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text("\n".join(sorted(urls)) + ("\n" if urls else ""), encoding="utf-8")
    return len(urls)


@trace
def _run_external(cmd: List[str], stdin_text: Optional[str] = None, timeout: Optional[int] = None) -> Tuple[int, str, str]:
    try:
        log.debug(f"exec: {' '.join(cmd)}")
        cp = subprocess.run(cmd, input=stdin_text, text=True, capture_output=True, timeout=timeout, check=False)
        return cp.returncode, cp.stdout, cp.stderr
    except Exception as e:

        return 1, "", f"exec error: {e}"

@trace
def _read_nonempty_lines(p: Path) -> List[str]:
    if not p.exists():
        return []
    lines = []
    for s in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = s.strip()
        if s:
            lines.append(s)
    return lines




@trace
def post_harvest_live_analysis(
    outdir: Path, harvest_dir: Path, map_sources_dir: Path,
    gf_dir: Optional[str], unfurl_bin: Optional[str],
    linkfinder: Optional[str], secretfinder: Optional[str],
    httpx_bin: Optional[str],
    max_js_bytes: int = 5 * 1024 * 1024,
    js_scan_only_alive: bool = False,
    js_scan_include_local: bool = False,
):
    """
    Build live URL sets, (optionally) narrow to alive with httpx, then
    run LinkFinder & SecretFinder on:
      - URLs from analysis/jsfile_links.txt (optionally intersected with alive URLs)
      - Locally harvested JS and sourcemap-chased sources (if enabled)
    Outputs:
      analysis/live/alive_urls.txt
      analysis/live/js_endpoints.txt
      analysis/live/js_secrets.txt
    """
    # Auto-detect tool paths if runner didn't pass them
    linkfinder = linkfinder or shutil.which('linkfinder') or shutil.which('LinkFinder')
    secretfinder = secretfinder or shutil.which('SecretFinder') or shutil.which('secretfinder')
    httpx_bin = httpx_bin or shutil.which('httpx')

    live_dir = outdir / "analysis" / "live"
    live_dir.mkdir(parents=True, exist_ok=True)

    live_urls_file = live_dir / "live_urls.txt"
    alive_urls_file = live_dir / "alive_urls.txt"
    endpoints_out = live_dir / "js_endpoints.txt"
    secrets_out = live_dir / "js_secrets.txt"
    endpoints_out.write_text("", encoding="utf-8")
    secrets_out.write_text("", encoding="utf-8")

    # 1) Collect all final URLs we just harvested (.url sidecars)
    count = _build_live_urls_list(harvest_dir, live_urls_file)
    log.info(f"post-harvest: collected {count} live candidates -> {live_urls_file}")
    
    def _httpx_supports_pd_flags(binpath: str) -> bool:
        """Detect ProjectDiscovery httpx (Go) vs python 'httpx' package CLI."""
        try:
            rc, out, err = _run_external([binpath, "-h"], timeout=8)
            help_txt = (out or "") + "\n" + (err or "")
            return ("-silent" in help_txt) and ("-mc" in help_txt)
        except Exception:
            return False

# 2) Alive filtering with httpx (2xx/3xx only) if available
    # NOTE: We only support ProjectDiscovery 'httpx' here (flags like -silent).
    # If the user has the Python 'httpx' CLI installed instead, we skip alive filtering.
    alive_set: Set[str] = set()
    if httpx_bin and shutil.which(httpx_bin) and (not _httpx_supports_pd_flags(httpx_bin)):
        log.warning("httpx at %s does not look like ProjectDiscovery httpx (missing -silent/-mc). Skipping alive filter.", httpx_bin)

    if httpx_bin and shutil.which(httpx_bin) and _httpx_supports_pd_flags(httpx_bin):
        try:
            # Detect ProjectDiscovery httpx by checking help output for '-silent'
            rc_h, out_h, err_h = _run_external([httpx_bin, "-h"], timeout=10)
            help_txt = (out_h or "") + "\n" + (err_h or "")
            if "-silent" not in help_txt and "--silent" not in help_txt:
                log.warning("httpx binary does not look like ProjectDiscovery httpx (no -silent in -h); skipping alive filter.")
            else:
                url_text = live_urls_file.read_text(encoding="utf-8", errors="ignore")
                # ProjectDiscovery httpx expects a list file via -l (most reliable across versions).
                # Feeding via stdin is not consistently supported.
                import tempfile
                tmp_list_path = None
                try:
                    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8") as tf:
                        tf.write(url_text)
                        tmp_list_path = tf.name
                    ok, out, err = _run_external(
                        [
                            httpx_bin, "-silent", "-follow-redirects",
                            "-mc",
                            "200,201,202,203,204,205,206,300,301,302,303,304,307,308",
                            "-l", tmp_list_path,
                        ],
                        timeout=180,
                    )
                finally:
                    if tmp_list_path:
                        try:
                            os.unlink(tmp_list_path)
                        except Exception:
                            pass
                if ok == 0 and out:
                    lines = [s.strip() for s in out.splitlines() if s.strip()]
                    alive_set.update(lines)
                    alive_urls_file.write_text("\n".join(sorted(alive_set)) + ("\n" if alive_set else ""), encoding="utf-8")
                    log.info(f"post-harvest: alive URLs -> {alive_urls_file} ({len(alive_set)})")
                else:
                    if err and err.strip():
                        log.warning(f"httpx stderr: {err.strip()[:300]}")
                    log.warning("httpx run failed or returned no output; continuing without alive filter.")
        except Exception as e:
            log.warning(f"httpx execution failed: {e}")

# 3) Build the URL list of JS to scan

    #    Start from archived .js list (pre-analysis)
    jsfile_links = (outdir / "analysis" / "jsfile_links.txt")
    url_targets: Set[str] = set(_read_nonempty_lines(jsfile_links))
    if js_scan_only_alive and alive_set:
        url_targets = {u for u in url_targets if u in alive_set}

    # 4) Optionally add local JS bodies (harvest + map_sources)
    local_targets: List[Path] = []
    if js_scan_include_local:
        TEXT_EXTS = {".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".vue", ".svelte", ".map"}
        for pth in harvest_dir.iterdir():
            if pth.is_file() and pth.suffix.lower() in TEXT_EXTS and pth.stat().st_size <= max_js_bytes:
                # Ignore .url/.hdr here
                if pth.suffix.lower() in {".url", ".hdr"}:
                    continue
                local_targets.append(pth)
        if map_sources_dir.exists():
            for pth in map_sources_dir.rglob("*"):
                try:
                    if pth.is_file() and pth.suffix.lower() in TEXT_EXTS and pth.stat().st_size <= max_js_bytes:
                        local_targets.append(pth)
                except FileNotFoundError:
                    continue
        log.info(f"post-harvest: local JS selected for scanning = {len(local_targets)}")

    # 5) Run LinkFinder & SecretFinder
    def _run_linkfinder_on_input(inp: str) -> List[str]:
        if not linkfinder or not shutil.which(linkfinder):
            return []
        rc, out, err = _run_external([linkfinder, "-i", inp, "-o", "cli"], timeout=90)
        if rc != 0 and err.strip():
            log.debug(f"LinkFinder err on {inp[:200]}: {err.strip()[:200]}")
        return [s.strip() for s in out.splitlines() if s.strip()]

    def _run_secretfinder_on_input(inp: str) -> List[str]:
        if not secretfinder or not shutil.which(secretfinder):
            return []
        # SecretFinder.py typical CLI: -i INPUT -o cli
        rc, out, err = _run_external([secretfinder, "-i", inp, "-o", "cli"], timeout=90)
        if rc != 0 and err.strip():
            log.debug(f"SecretFinder err on {inp[:200]}: {err.strip()[:200]}")
        return [s.strip() for s in out.splitlines() if s.strip()]

    endpoints: List[str] = []
    secrets: List[str] = []

    # URLs first (remote)
    for u in sorted(url_targets):
        endpoints.extend(_run_linkfinder_on_input(u))
        secrets.extend(_run_secretfinder_on_input(u))

    # Locals (files) next
    for pth in local_targets:
        try:
            endpoints.extend(_run_linkfinder_on_input(str(pth)))
            secrets.extend(_run_secretfinder_on_input(str(pth)))
        except Exception:
            continue

    # Dedup and write
    endpoints = sorted({e for e in endpoints})
    secrets = sorted({s for s in secrets})
    endpoints_out.write_text("\n".join(endpoints) + ("\n" if endpoints else ""), encoding="utf-8")
    secrets_out.write_text("\n".join(secrets) + ("\n" if secrets else ""), encoding="utf-8")
    log.info(f"post-harvest: js_endpoints={len(endpoints)} -> {endpoints_out}")
    log.info(f"post-harvest: js_secrets={len(secrets)} -> {secrets_out}")

@trace
async def main():
    parser = argparse.ArgumentParser()

    # Auto-discover & interaction
    parser.add_argument(
        "--auto-discover",
        default=None,
        help=(
            "Base directory to scan for Phase-1 outputs per domain; "
            "builds inputs/merged_urls.txt per domain"
        ),
    )
    parser.add_argument(
        "--interactive",
        choices=["auto", "yes", "no"],
        default="auto",
        help="Interactive picker. 'auto' = yes if TTY, else no",
    )
    parser.add_argument(
        "--domain-filter",
        default=None,
        help="Glob or regex to limit domains when using --auto-discover",
    )
    parser.add_argument(
        "--include-globs",
        default="*.urls,*.links",
        help=(
            "Comma globs considered URL lists during auto-discover "
            "(in addition to canonical files)"
        ),
    )
    parser.add_argument(
        "--include-host-globs",
        default="*.hosts",
        help=(
            "Comma globs considered host lists during auto-discover "
            "(in addition to canonical files)"
        ),
    )
    parser.add_argument(
        "--noninteractive-policy",
        choices=["canonical", "all", "none"],
        default="canonical",
        help="Selection policy if --interactive=no (or auto no)",
    )

    # URL / scope (manual mode)
    parser.add_argument("--urls", help="Primary URL list (one per line)")
    parser.add_argument(
        "--merge-urls",
        default=None,
        help="Comma-separated list of additional URL files to union+dedupe with --urls",
    )
    parser.add_argument(
        "--seed-hosts",
        default=None,
        help=(
            "Comma-separated list of files containing hostnames to expand into safe asset URLs "
            "(intersected with --scope)"
        ),
    )
    parser.add_argument(
        "--seed-default-paths",
        default=(
            "/robots.txt,/sitemap.xml,/favicon.ico,/.well-known/security.txt,/.well-known/assetlinks.json,/index.html"
        ),
        help="Comma-separated list of safe paths to build from seed hosts",
    )
    parser.add_argument(
        "--scope",
        required=True,
        help="File with allowed domains (exact host match)",
    )
    parser.add_argument(
        "--domain",
        default=None,
        help=(
            "Domain label for output subfolder: <output>/<domain>/. "
            "If omitted, inferred from scope when single entry."
        ),
    )
    parser.add_argument(
        "--output",
        required=True,
        help="Base output directory (or per-domain root when --domain/auto)",
    )

    # Downloader / ethics
    parser.add_argument("--concurrency", type=int, default=4)
    parser.add_argument("--rps", type=float, default=0.5)
    parser.add_argument("--respect-robots", choices=["yes", "no"], default="yes")
    parser.add_argument("--max-size", type=int, default=5 * 1024 * 1024)
    parser.add_argument("--timeout", type=int, default=60, help="Per-request timeout")
    parser.add_argument("--retries", type=int, default=2, help="Retries on transient errors")
    parser.add_argument(
        "--retry-backoff-cap",
        type=int,
        default=8,
        help="Max backoff seconds (exponential cap)",
    )
    parser.add_argument(
        "--respect-retry-after",
        choices=["yes", "no"],
        default="yes",
        help="Honor server Retry-After / X-RateLimit-Reset headers",
    )
    parser.add_argument(
        "--retry-after-cap",
        type=int,
        default=120,
        help="Cap seconds to wait when honoring Retry-After / X-RateLimit-Reset",
    )
    parser.add_argument(
        "--user-agent",
        default="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/132.0.0.0 Safari/537.36",
    )
    parser.add_argument(
        "--write-headers",
        choices=["yes", "no"],
        default="no",
        help="Write .hdr files next to harvested bodies",
    )
    parser.add_argument(
        "--extra-exts",
        default="",
        help=(
            "Comma-separated additional extensions to treat as interesting for harvesting "
            "(e.g., '.pdf,.zip,.docx')"
        ),
    )

    # Sourcemaps
    parser.add_argument("--enable-sourcemaps", choices=["yes", "no"], default="yes")
    parser.add_argument("--max-map-size", type=int, default=10 * 1024 * 1024)
    parser.add_argument("--map-retries", type=int, default=2)
    parser.add_argument("--map-timeout", type=int, default=30)
    parser.add_argument("--map-head-timeout", type=int, default=10)
    parser.add_argument(
        "--map-extract-sources",
        choices=["yes", "no"],
        default="yes",
        help="Extract 'sources' array to a manifest (no live fetch)",
    )
    parser.add_argument(
        "--map-chase-sources",
        choices=["yes", "no"],
        default="no",
        help="Reserved for future passive resolution; no live fetch here",
    )
    parser.add_argument(
        "--map-sources-dir",
        default=None,
        help="Folder to store map sources manifests (default: <output>/map_sources)",
    )

    # GF / UCA
    parser.add_argument("--gf-patterns", default=None, help="GF patterns directory (optional)")
    parser.add_argument("--custom-patterns", default=None)

    parser.add_argument(
        "--gf-timeout",
        type=int,
        default=8,
        help="Per gf pattern timeout in seconds (default: 8)",
    )
    parser.add_argument(
        "--gf-include",
        default=None,
        help=("Comma-separated gf patterns to run (e.g., "
              "'aws-keys_secrets,github_secrets'). If omitted, the default set is used."),
    )
    parser.add_argument("--ignore-file", default=None)
    parser.add_argument("--exclude-url-rules-json", default=None,
        help="Optional JSON file with path-level exclusions: list of {host, path_regex}. Skipped before fetch.")
    parser.add_argument(
        "--uca-exts",
        default=(
            ".html,.xhtml,.js,.mjs,.cjs,.ts,.tsx,.jsx,.vue,.svelte,.php,.asp,.aspx,.jsp,.jspx,.json,.json5,.xml,.svg,.css,.scss,.less,.webmanifest"
        ),
        help="Comma-separated extensions to pass to UCA curation",
    )
    parser.add_argument("--include-maps-in-uca", choices=["yes", "no"], default="no")
    parser.add_argument("--uca-link-mode", choices=["symlink", "copy"], default="symlink")
    parser.add_argument("--uca-format", choices=["html", "json", "csv"], default="html")
    parser.add_argument("--uca-enable-semgrep", choices=["yes", "no"], default="no")
    parser.add_argument("--uca-enable-debug-log", choices=["yes", "no"], default="no")
    parser.add_argument("--uca-scan-all-text", choices=["yes", "no"], default="yes")

    # venv / deps
    parser.add_argument(
        "--venv",
        default=None,
        help="Path to a Python virtualenv for running code_analyzer.pyz",
    )
    parser.add_argument(
        "--venv-create", action="store_true", help="Create the venv if it does not exist"
    )
    parser.add_argument(
        "--venv-ensure-packages",
        default=None,
        help=(
            "Comma-separated packages to preinstall in the venv (e.g. 'ijson,pyaml,semgrep,PyYAML')"
        ),
    )
    parser.add_argument(
        "--uca-reqs", default=None, help="Requirements file to install into the venv before UCA"
    )
    parser.add_argument(
        "--uca-wheels", default=None, help="Wheelhouse directory for offline installs"
    )
    parser.add_argument(
        "--uca-auto-install-missing", choices=["yes", "no"], default="yes"
    )
    parser.add_argument("--pip-extra-index-url", default=None)

    # tools for URL analysis
    parser.add_argument("--unfurl", default=None, help="Path to unfurl (optional)")
    parser.add_argument(
        "--httpx",
        default=None,
        help="Path to httpx (optional for analysis alive list)",
    )

    # NEW: Post-harvest live JS analysis options
    parser.add_argument(
        "--post-harvest-js-tools",
        choices=["yes", "no"],
        default="yes",
        help=(
            "Run LinkFinder/SecretFinder on harvested JS + sourcemap sources into analysis/live/"
        ),
    )
    parser.add_argument(
        "--linkfinder",
        default=None,
        help="Executable path to LinkFinder (e.g., /path/linkfinder.py)",
    )
    parser.add_argument(
        "--secretfinder",
        default=None,
        help="Executable path to SecretFinder (e.g., /path/SecretFinder.py)",
    )
    parser.add_argument(
        "--post-max-js-size",
        type=int,
        default=5 * 1024 * 1024,
        help="Max JS bytes to scan in post-harvest analysis",
    )
    parser.add_argument(
        "--js-scan-only-alive",
        choices=["yes", "no"],
        default="no",
        help=(
            "If 'yes', intersect analysis/jsfile_links.txt with analysis/live/alive_urls.txt before scanning"
        ),
    )
    parser.add_argument(
        "--js-scan-include-local",
        choices=["yes", "no"],
        default="no",
        help=(
            "If 'yes', also run tools on locally harvested JS and map-sourced JS"
        ),
    )

    # --- offline analyzers (pre-live, offline only) ---
    parser.add_argument("--enable-offline-analyzers", choices=["yes","no"], default="no",
                    help="Run offline analyzers (Retire.js, TruffleHog, Wappalyzer) on harvested files before any live scans")
    parser.add_argument("--retirejs", default=None, help="Path to retire (Node CLI, e.g. 'retire')")
    parser.add_argument("--trufflehog", default=None, help="Path to trufflehog binary (v3+)")
    parser.add_argument("--wappalyzer", default=None, help="Path to wappalyzer CLI (e.g. 'wappalyzer')")
    parser.add_argument("--offline-timeout", type=int, default=120,
                    help="Per-tool timeout (seconds) for offline analyzers")
    parser.add_argument("--offline-max-files", type=int, default=20000,
                    help="Max files to consider for offline analyzers")
    
    parser.add_argument("--whatweb-offline", default=None, help="Path to whatweb CLI (offline via local server)")
    parser.add_argument("--whatweb-max-targets", type=int, default=500,
                    help="Max number of local HTML files to sample for WhatWeb/heuristics")

    # --- post-analysis web scanners (online; take alive/interesting as input) ---
    parser.add_argument("--enable-web-scanners", choices=["yes","no"], default="no",
                        help="Run online web scanners after post-harvest analysis (uses analysis/live/alive_urls.txt & analysis/interesting.txt)")

    # WhatWeb
    parser.add_argument("--whatweb", default=None, help="Path to whatweb CLI (online mode)")

    # Nuclei
    parser.add_argument("--nuclei", default=None, help="Path to nuclei binary")
    parser.add_argument("--nuclei-templates", default=os.getenv("NUCLEI_TEMPLATES", None),
                        help="Path to nuclei templates")
    parser.add_argument("--nuclei-rate", type=float, default=2.0, help="Nuclei rate limit (req/s)")
    parser.add_argument("--nuclei-concurrency", type=int, default=50, help="Nuclei concurrency")
    parser.add_argument("--nuclei-severity", default="low,medium,high,critical", help="Nuclei severities")
    parser.add_argument("--nuclei-tags", default="cves,exposure,misconfig,tech", help="Nuclei tags")

    # Nikto / Wapiti
    parser.add_argument("--nikto", default=None, help="Path to nikto")
    parser.add_argument("--wapiti", default=None, help="Path to wapiti")
    parser.add_argument("--wapiti-modules", default="xss,sql,ssrf", help="Wapiti modules list (comma-separated)")
    parser.add_argument("--wapiti-strength", default="normal", help="Wapiti strength (light, normal, heavy)")

    # ZAP
    parser.add_argument("--zap-baseline", default=None, help="Path to zap-baseline.py")
    parser.add_argument("--zap-full", default=None, help="Path to zap-full-scan.py")
    parser.add_argument("--zap-active-minutes", type=int, default=5, help="ZAP full-scan active minutes")
    parser.add_argument("--zap-max-targets", type=int, default=10, help="Max targets for ZAP")

    # Arachni
    parser.add_argument("--arachni", default=None, help="Path to arachni")
    parser.add_argument("--arachni-max-targets", type=int, default=5, help="Max targets for Arachni")

    # Skipfish
    parser.add_argument("--skipfish", default=None, help="Path to skipfish")
    parser.add_argument("--skipfish-wordlist", default=None, help="Skipfish wordlist (optional)")
    parser.add_argument("--skipfish-max-targets", type=int, default=10, help="Max targets for Skipfish")

    # Shared
    parser.add_argument("--scanners-timeout", type=int, default=600, help="Per-tool timeout (seconds)")
    parser.add_argument("--scanners-max-targets", type=int, default=500, help="Cap alive targets fed to scanners")

    # Per-scanner enables (default 'yes' so behavior is unchanged once --enable-web-scanners yes)
    parser.add_argument("--enable-whatweb", choices=["yes","no"], default="yes",
                        help="Enable WhatWeb in post-analysis")
    parser.add_argument("--enable-nuclei", choices=["yes","no"], default="yes",
                        help="Enable Nuclei in post-analysis")
    parser.add_argument("--enable-nikto", choices=["yes","no"], default="yes",
                        help="Enable Nikto in post-analysis")
    parser.add_argument("--enable-wapiti", choices=["yes","no"], default="yes",
                        help="Enable Wapiti in post-analysis")
    parser.add_argument("--enable-zap", choices=["yes","no"], default="yes",
                        help="Enable ZAP baseline/full in post-analysis")
    parser.add_argument("--enable-arachni", choices=["yes","no"], default="yes",
                        help="Enable Arachni in post-analysis")
    parser.add_argument("--enable-skipfish", choices=["yes","no"], default="yes",
                        help="Enable Skipfish in post-analysis")


    args = parser.parse_args()

    # runtime interesting extensions
    @trace
    def _parse_ext_list(s: str) -> Set[str]:
        exts = set()
        for item in (s or "").split(","):
            it = item.strip()
            if not it:
                continue
            if not it.startswith("."):
                it = "." + it
            exts.add(it.lower())
        return exts

    RUNTIME_INTERESTING_EXTS = set(INTERESTING_EXTS_DEFAULT) | _parse_ext_list(args.extra_exts)
    global PATH_HINTS
    PATH_HINTS = tuple(sorted(RUNTIME_INTERESTING_EXTS, key=len, reverse=True))

    # Load scope & compute per-domain output root
    allowed = load_scope(args.scope)
    exclude_url_rules = load_exclude_url_rules(args.exclude_url_rules_json)
    base_out = Path(args.output)

    # Auto-discover flow?
    auto = args.auto_discover is not None
    if auto:
        interactive = (args.interactive == "yes") or (
            args.interactive == "auto" and _is_tty()
        )
        include_globs = [
            g.strip() for g in (args.include_globs or "").split(",") if g.strip()
        ]
        include_host_globs = [
            g.strip() for g in (args.include_host_globs or "").split(",") if g.strip()
        ]
        discovered = _discover_phase1_files(
            Path(args.auto_discover),
            include_globs=include_globs,
            include_host_globs=include_host_globs,
            domain_filter=args.domain_filter,
        )
        if not discovered:
            log.warning(
                "Auto-discover found no candidate files. Falling back to manual --urls path."
            )
        else:
            for domain_label in sorted(discovered.keys()):
                dl = domain_label.lower().strip().strip('.')
                if dl not in allowed:
                    log.info(f"[{domain_label}] skipping (domain not in --scope)")
                    continue
                outdir = base_out / domain_label
                harvest_dir = outdir / "harvest"
                gf_outdir = outdir / "gf_out"
                uca_outdir = outdir / "uca_out"
                uca_src_dir = outdir / "uca_src"
                map_sources_dir = outdir / "map_sources"
                for d in (harvest_dir, gf_outdir, uca_outdir):
                    os.makedirs(d, exist_ok=True)

                safe_paths = [
                    s.strip() for s in (args.seed_default_paths or "").split(",") if s.strip()
                ]
                merged_urls = _build_auto_inputs_for_domain(
                    domain_label,
                    discovered,
                    allowed,
                    exclude_url_rules=exclude_url_rules,
                    outdir=outdir,
                    interactive=interactive,
                    noninteractive_policy=args.noninteractive_policy,
                    safe_paths=safe_paths,
                )
                if not merged_urls:
                    log.info(f"[{domain_label}] skipping (no merged inputs).")
                    continue

                await _run_pipeline_for_single_domain(
                    urls_file=merged_urls,
                    allowed=allowed,
                    exclude_url_rules=exclude_url_rules,
                    user_agent=args.user_agent,
                    outdir=outdir,
                    harvest_dir=harvest_dir,
                    gf_outdir=gf_outdir,
                    uca_outdir=uca_outdir,
                    uca_src_dir=uca_src_dir,
                    map_sources_dir=map_sources_dir,
                    args=args,
                    interesting_exts=RUNTIME_INTERESTING_EXTS,
                )
            return

    # Manual flow
    domain_label = _infer_domain_label(args, allowed)
    outdir = (base_out / domain_label) if domain_label else base_out
    harvest_dir = outdir / "harvest"
    gf_outdir = outdir / "gf_out"
    uca_outdir = outdir / "uca_out"
    uca_src_dir = outdir / "uca_src"
    map_sources_dir = (
        Path(args.map_sources_dir) if args.map_sources_dir else (outdir / "map_sources")
    )
    for d in (harvest_dir, gf_outdir, uca_outdir):
        os.makedirs(d, exist_ok=True)
    log.info(f"Output dirs ready base={outdir}")

    if not args.urls:
        raise SystemExit("--urls is required when --auto-discover is not used")

    await _run_pipeline_for_single_domain(
        urls_file=Path(args.urls),
        allowed=allowed,
                    exclude_url_rules=exclude_url_rules,
        user_agent=args.user_agent,
        outdir=outdir,
        harvest_dir=harvest_dir,
        gf_outdir=gf_outdir,
        uca_outdir=uca_outdir,
        uca_src_dir=uca_src_dir,
        map_sources_dir=map_sources_dir,
        args=args,
        interesting_exts=RUNTIME_INTERESTING_EXTS,
    )


@trace
async def _run_pipeline_for_single_domain(
    *,
    urls_file: Path,
    allowed: Set[str],
    exclude_url_rules: Optional[list],
    user_agent: str,
    outdir: Path,
    harvest_dir: Path,
    gf_outdir: Path,
    uca_outdir: Path,
    uca_src_dir: Path,
    map_sources_dir: Path,
    args: argparse.Namespace,
    interesting_exts: Set[str],
):
    # Build candidate URL set
    candidate_urls: List[str] = []
    candidate_urls.extend(_read_lines(Path(urls_file)))

    if args.merge_urls:
        more_files = [s.strip() for s in args.merge_urls.split(",") if s.strip()]
        filtered_more_files = [
            f for f in more_files
            if not (("jquery-ui" in f or "select2" in f or "bootstrap.min.js" in f or "getLanguages" in f)
                    or (os.path.exists(f) and os.path.getsize(f) > 400*1024))
        ]
        merged = _union_url_files(filtered_more_files)
        candidate_urls.extend(merged)

    if args.seed_hosts:
        seed_files = [s.strip() for s in args.seed_hosts.split(",") if s.strip()]
        filtered_seed_files = [
            f for f in seed_files
            if not (("jquery-ui" in f or "select2" in f or "bootstrap.min.js" in f or "getLanguages" in f)
                    or (os.path.exists(f) and os.path.getsize(f) > 400*1024))
        ]
        safe_paths = [s.strip() for s in (args.seed_default_paths or "").split(",") if s.strip()]
        seed_urls = _expand_seed_hosts_to_urls(filtered_seed_files, safe_paths, allowed)
        candidate_urls.extend(seed_urls)

    # Scope + robots filter
    urls: List[str] = []
    total = 0
    for raw in candidate_urls:
        total += 1
        url = normalize_url_line(raw)
        if not url:
            continue
        if not in_scope(url, allowed):
            continue
        if excluded_by_url_rules(url, exclude_url_rules):
            log.debug(f"filter: excluded-by-rule url={url}")
            continue
        if args.respect_robots == "yes":
            if not await allowed_by_robots(url, user_agent):
                log.debug(f"filter: robots disallow url={url}")
                continue
        urls.append(url)

    log.info(f"Filter complete kept={len(urls)}/{total}")
    print(f"[+] {len(urls)} URLs in scope after filtering.")

    if not urls:
        log.info("No in-scope URLs after filtering; skipping harvest/analyzers for this domain.")
        return


    # -------- URL analysis (writes <out>/analysis/*) BEFORE harvesting/uca (treat as archived view)
    url_analysis(
        urls=urls,
        outdir=outdir,
        gf_dir=args.gf_patterns,
        unfurl_bin=args.unfurl,
        httpx_bin=args.httpx,
    )

    # Download
    sem = asyncio.Semaphore(max(1, args.concurrency))
    host_gate = HostRateGate()
    async with aiohttp.ClientSession() as session:
        tasks = [
            download_url(
                session,
                sem,
                u,
                harvest_dir,
                user_agent,
                args.max_size,
                args.rps,
                args.timeout,
                args.retries,
                args.retry_backoff_cap,
                respect_retry_after=(args.respect_retry_after == "yes"),
                retry_after_cap=args.retry_after_cap,
                host_gate=host_gate,
                write_headers=(args.write_headers == "yes"),
                interesting_exts=interesting_exts,
                allowed_domains=allowed,
                exclude_url_rules=exclude_url_rules,
            )
            for u in urls
        ]
        results = await asyncio.gather(*tasks)
        succeeded = sum(1 for ok in results if ok)
        log.info(f"Downloads finished ok={succeeded} total={len(urls)}")

        # Sourcemaps
        if args.enable_sourcemaps == "yes":
            maps_saved, js_scanned = await discover_and_fetch_maps(
                session=session,
                sem=sem,
                host_gate=host_gate,
                harvest_dir=harvest_dir,
                allowed_domains=allowed,
                user_agent=user_agent,
                respect_retry_after=(args.respect_retry_after == "yes"),
                retry_after_cap=args.retry_after_cap,
                rps=args.rps,
                head_timeout=args.map_head_timeout,
                map_timeout=args.map_timeout,
                map_retries=args.map_retries,
                backoff_cap=args.retry_backoff_cap,
                max_map_size=args.max_map_size,
                respect_robots_flag=(args.respect_robots == "yes"),
                extract_sources=(args.map_extract_sources == "yes"),
                chase_sources=(args.map_chase_sources == "yes"),
                map_sources_dir=map_sources_dir,
            )
            log.info(f"Sourcemaps: scanned_js={js_scanned} maps_saved={maps_saved}")

    if args.enable_offline_analyzers == "yes":
        try:
            # Auto-detect offline tools if runner didn't pass explicit paths
            if not args.retirejs:
                args.retirejs = shutil.which('retire')
            if not args.trufflehog:
                args.trufflehog = shutil.which('trufflehog')
            if not args.wappalyzer:
                args.wappalyzer = shutil.which('wappalyzer')
            if not getattr(args, 'whatweb_offline', None):
                args.whatweb_offline = shutil.which('whatweb')

            
            # inside if args.enable_offline_analyzers == "yes":
            run_offline_analyzers(
                outdir=outdir,
                harvest_dir=harvest_dir,
                map_sources_dir=map_sources_dir,
                retirejs_bin=args.retirejs,
                trufflehog_bin=args.trufflehog,
                wappalyzer_bin=args.wappalyzer,
                timeout_s=getattr(args, "offline_timeout", 120),
                max_files=getattr(args, "offline_max_files", 20000),
                whatweb_bin=getattr(args, "whatweb_offline", None),   # <- changed
                whatweb_max_targets=getattr(args, "whatweb_max_targets", 500),
            )
        except Exception as e:
            log.warning("offline analyzers failed: %s", e)


    tech_hints = (outdir / "analysis" / "offline" / "tech_hints.txt")        


    
    
    
    
    
    
    # Optional GF on harvested files
    if args.gf_patterns:
        run_gf(
            harvest_dir,
            args.gf_patterns,
            gf_outdir,
            max_bytes=500_000,  # or 1_000_000 if you prefer
            per_call_timeout=args.gf_timeout,
            scan_html=False,  # turn on only if you want URL/script extraction
            include_patterns=(args.gf_include.split(',') if args.gf_include else None),  # or a list: ["aws-keys_secrets","google-keys_secrets",...]
        )

    # NEW: Post-harvest live analysis (live/ subfolder)
    if args.post_harvest_js_tools == "yes":
        post_harvest_live_analysis(
            outdir=outdir,
            harvest_dir=harvest_dir,
            map_sources_dir=map_sources_dir,
            gf_dir=args.gf_patterns,
            unfurl_bin=args.unfurl,
            linkfinder=args.linkfinder,
            secretfinder=args.secretfinder,
            httpx_bin=args.httpx,
            max_js_bytes=args.post_max_js_size,
            js_scan_only_alive=(args.js_scan_only_alive == "yes"),
            js_scan_include_local=(args.js_scan_include_local == "yes"),
        )

    # After post_harvest_live_analysis produced analysis/live/alive_urls.txt & analysis/interesting.txt
    if args.enable_web_scanners == "yes":
        domain_out = outdir
        alive_file = outdir / "analysis" / "live" / "alive_urls.txt"
        #alive_file = domain_out / "analysis" / "live" / "alive_urls.txt"
        interesting_file = outdir / "analysis" / "interesting.txt"

        if not alive_file.exists():
            log.warning("web-scanners: %s not found; skipping scanners", alive_file)
        else:
            try:
                run_post_scanners(
                    outdir=domain_out,
                    alive_file=alive_file,
                    interesting_file=interesting_file,
                    timeout_s=getattr(args, "scanners_timeout", 600),
                    max_targets=getattr(args, "scanners_max_targets", 500),

                    # WhatWeb
                    whatweb_bin=(args.whatweb if args.enable_whatweb == "yes" else None),

                    # Nuclei
                    nuclei_bin=(args.nuclei if args.enable_nuclei == "yes" else None),
                    nuclei_templates=(args.nuclei_templates if args.enable_nuclei == "yes" else None),
                    nuclei_rate=getattr(args, "nuclei_rate", 2.0),
                    nuclei_concurrency=getattr(args, "nuclei_concurrency", 50),
                    nuclei_severity=getattr(args, "nuclei_severity", "low,medium,high,critical"),
                    nuclei_tags=getattr(args, "nuclei_tags", "cves,exposure,misconfig,tech"),
                    nuclei_extra_tags=(tech_hints if tech_hints.exists() else None),

                    # Nikto
                    nikto_bin=(args.nikto if args.enable_nikto == "yes" else None),

                    # Wapiti
                    wapiti_bin=(args.wapiti if args.enable_wapiti == "yes" else None),
                    wapiti_modules=getattr(args, "wapiti_modules", "xss,sql,ssrf"),
                    wapiti_strength=getattr(args, "wapiti_strength", "normal"),

                    # ZAP (both baseline/full share same gate)
                    zap_baseline=(args.zap_baseline if args.enable_zap == "yes" else None),
                    zap_full=(args.zap_full if args.enable_zap == "yes" else None),
                    zap_active_minutes=getattr(args, "zap_active_minutes", 5),
                    zap_max_targets=getattr(args, "zap_max_targets", 10),

                    # Arachni
                    arachni_bin=(args.arachni if args.enable_arachni == "yes" else None),
                    arachni_max_targets=getattr(args, "arachni_max_targets", 5),

                    # Skipfish
                    skipfish_bin=(args.skipfish if args.enable_skipfish == "yes" else None),
                    skipfish_wordlist=getattr(args, "skipfish_wordlist", None),
                    skipfish_max_targets=getattr(args, "skipfish_max_targets", 10),
                )

            except Exception as e:
                log.warning("web-scanners failed: %s", e)
    

    # Prepare venv (optional) for UCA
    venv_py: Optional[Path] = None
    if args.venv:
        try:
            venv_py = ensure_venv(Path(args.venv), create=args.venv_create)
            if args.venv_ensure_packages:
                packages = [
                    p.strip() for p in args.venv_ensure_packages.split(",") if p.strip()
                ]
                pip_install_packages(
                    venv_py,
                    packages,
                    wheels_dir=Path(args.uca_wheels) if args.uca_wheels else None,
                    extra_index=args.pip_extra_index_url,
                )
            if args.uca_reqs:
                pip_install_requirements(
                    venv_py,
                    Path(args.uca_reqs),
                    wheels_dir=Path(args.uca_wheels) if args.uca_wheels else None,
                    extra_index=args.pip_extra_index_url,
                )
        except Exception as e:
            log.error(f"Venv setup failed: {e} (continuing without venv)")
            venv_py = None

    # Curate ONLY interesting files for UCA
    uca_exts = [e.strip() for e in args.uca_exts.split(",") if e.strip()]
    curated_count = build_uca_source(
        harvest_dir,
        uca_src_dir,
        uca_exts,
        include_maps=(args.include_maps_in_uca == "yes"),
        link_mode=args.uca_link_mode,
    )
    if curated_count == 0:
        log.warning(
            "No files matched --uca-exts (and map opt); skipping UCA for this domain."
        )
        return

    # Run UCA (live streaming)
    auto_install = args.uca_auto_install_missing == "yes"
    run_uca(
        uca_src_dir,
        uca_outdir,
        args.custom_patterns,
        args.ignore_file,
        venv_py=venv_py,
        auto_install_missing=auto_install,
        wheels_dir=Path(args.uca_wheels) if args.uca_wheels else None,
        extra_index=args.pip_extra_index_url,
        uca_format=args.uca_format,
        uca_enable_semgrep=(args.uca_enable_semgrep == "yes"),
        uca_enable_debug_log=(args.uca_enable_debug_log == "yes"),
        uca_scan_all_text=(args.uca_scan_all_text == "yes"),
    )


if __name__ == "__main__":
    asyncio.run(main())

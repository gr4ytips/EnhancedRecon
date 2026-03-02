#!/usr/bin/env python3
# recon_pipeline.py — Phase 1 (Passive-first) Recon Aggregator (v1.5 Unified Corpus)
# - Per-domain output folders under --outdir
# - Core: Wayback + GAU collection -> cleaned -> (optional) strict liveness with httpx (batched)
# - Passive add-ons (toggleable): CT (crt.sh + certspotter), GitHub subdomains, registry OSINT (PyPI/NPM),
#   Shodan (metadata via API), PDNS via SecurityTrails, Censys hosts (API, PAT or ID/Secret), Wayback CDX deep.
#
# UPDATES v1.5:
# - Unified Body Storage: Wayback bodies now save to 'cc_bodies' so phase1_addons can scan them for secrets.
#
# Example:
#   python3 recon_pipeline.py \
#     -i allowed_domains.txt \
#     -o phase1_outputs \
#     --verbose \
#     --passive-only yes \
#     --enable-ct yes \
#     --enable-github-osint yes \
#     --enable-registry-osint yes \
#     --enable-shodan yes \
#     --enable-pdns yes \
#     --enable-censys yes \
#     --enable-wayback-cdx yes \
#     --fetch-archive-bodies yes \
#     --enable-cc-bodies yes \
#     --waybackurls /usr/local/bin/waybackurls \
#     --gau /usr/local/bin/gau

from __future__ import annotations
import argparse, os, sys, subprocess, time, logging, json, re
from pathlib import Path
from typing import List, Set, Dict, Optional, Tuple
from urllib.parse import quote
from urllib.request import Request, urlopen
import urllib.parse
import shutil
import configparser, stat
import io, gzip, random

# --------------- Logging
log = logging.getLogger("phase1")
log.info("RUNNING: %s", __file__)

# --------------- IDN / punycode helpers
def _to_ascii_idna(name: str) -> str:
    if not name:
        return ""
    name = name.strip().strip(".")
    try:
        return name.encode("idna").decode("ascii")
    except Exception:
        return name.lower()

def _from_ascii_idna(name: str) -> str:
    if not name:
        return ""
    try:
        return name.encode("ascii","ignore").decode("ascii").encode("ascii").decode("idna")
    except Exception:
        return name

# --------------- Helpers

# --------------- Common Crawl body fetch (WARC byte-ranges) ---------------
def _cc_collect_hits(
    domain: str,
    *,
    collections: list[str],
    server_url: str,
    max_pages: int,
    rps: float,
    timeout: int,
    retries: int,
    cdx_from: str = "",
    cdx_to: str = "",
    mime_allow: Optional[set[str]] = None,
) -> list[dict]:
    """
    Return raw CC index hits with keys:
      url, filename, offset, length, mime, status, timestamp
    """
    import random

    hits: list[dict] = []
    interval = 1.0 / max(0.1, rps)
    jitter = 0.25 * interval
    mime_allow = mime_allow or set()

    for cid in collections:
        base = f"{server_url.rstrip('/')}/{cid}-index"

        # quick ping
        try:
            _ping = fetch_text(f"{base}?url=example.com&output=json&page=0", timeout=min(10, timeout))
        except Exception:
            _ping = ""
        if not _ping:
            log.debug("[%s] CC bodies idx %s: ping empty → skipping collection", domain, cid)
            continue

        for page in range(max_pages):
            q = [_seed_url_param(domain), "output=json", f"page={page}"]
            if cdx_from: q.append(f"from={cdx_from}")
            if cdx_to:   q.append(f"to={cdx_to}")
            # status 200 only; MIME filtering is enforced locally
            q.append("filter=status:200")
            url = f"{base}?{'&'.join(q)}"

            docs: list[dict] = []
            attempt = 0
            while attempt <= max(0, retries):
                try:
                    docs = fetch_json_lines(url, timeout=timeout)
                except Exception:
                    docs = []
                if docs:
                    break
                time.sleep(interval * (2 ** attempt) + random.uniform(0, jitter))
                attempt += 1

            if not docs:
                if page == 0:
                    log.debug("[%s] CC bodies idx %s: page 0 empty → skipping collection", domain, cid)
                else:
                    log.debug("[%s] CC bodies idx %s: page %d empty → paging exhausted", domain, cid, page)
                break

            got = 0
            for d in docs:
                fn = d.get("filename") or d.get("file")
                off = d.get("offset")
                ln  = d.get("length")
                ts  = (d.get("timestamp") or "").strip()
                u   = (d.get("url") or d.get("original") or "").strip()
                st  = str(d.get("status") or "")
                mm  = (d.get("mime") or d.get("mime-detected") or "").split(";")[0].strip().lower()
                if not (fn and off and ln and u and st == "200"):
                    continue
                # scope gate
                m = re.match(r"^https?://([^/]+)/", u, flags=re.I)
                if not (m and scoped(m.group(1).lower(), domain)):
                    continue
                if mime_allow and mm and mm not in mime_allow:
                    continue
                try:
                    hits.append({
                        "url": u, "filename": fn, "offset": int(off), "length": int(ln),
                        "timestamp": ts, "mime": mm, "status": 200,
                    })
                    got += 1
                except Exception:
                    continue

            log.info("[%s] CC bodies idx %s page %d: +%d (total=%d)", domain, cid, page, got, len(hits))
            time.sleep(interval + random.uniform(0, jitter))

    return hits

def collect_commoncrawl(
    domain: str,
    ddir: Path,
    *,
    max_pages: int = 5,
    rps: float = 1.0,
    timeout: int = 30,
    collections: Optional[str] = None,
    retries: int = 2,
    server_url: str = "https://index.commoncrawl.org",
) -> Path:
    """
    Pull URLs from a CDX server (default CC) into cc_urls.txt with polite paging & retries.
    """
    out = ddir / "cc_urls.txt"
    ensure_dir(ddir)
    urls: Set[str] = set()

    interval = 1.0 / max(0.1, rps)
    jitter = 0.25 * interval

    # Resolve collections
    if collections:
        col_list = [c.strip() for c in collections.split(",") if c.strip()]
    else:
        col_list = _latest_cc_main_collections(limit=3, timeout=timeout, server_url=server_url)

    import random

    for cid in col_list:
        base = f"{server_url.rstrip('/')}/{cid}-index"
        ping_url = f"{base}?url=example.com&output=json&page=0"
        try:
            _ping = fetch_text(ping_url, timeout=min(10, timeout))
        except Exception:
            _ping = ""
        if not _ping:
            log.debug("[%s] CC %s: ping returned empty → skipping collection.", domain, cid)
            continue

        for page in range(max_pages):
            q = f"{base}?{_seed_url_param(domain)}&output=json&page={page}"
            attempt = 0
            docs: List[dict] = []
            while attempt <= max(0, retries):
                try:
                    docs = fetch_json_lines(q, timeout=timeout)
                except Exception:
                    docs = []
                if docs:
                    break
                sleep_for = interval * (2 ** attempt) + random.uniform(0, jitter)
                time.sleep(sleep_for)
                attempt += 1

            if not docs:
                if page == 0:
                    log.debug("[%s] CC %s: page 0 empty → skipping collection.", domain, cid)
                else:
                    log.debug("[%s] CC %s: page %d empty → paging exhausted.", domain, cid, page)
                break

            got = 0
            for d in docs:
                u = (d.get("url") or d.get("original") or "").strip()
                if not (u.startswith("http://") or u.startswith("https://")):
                    continue
                m = re.match(r"^https?://([^/]+)/", u, flags=re.I)
                if not m:
                    continue
                host = m.group(1).lower()
                if scoped(host, domain):
                    urls.add(u)
                    got += 1

            log.info("[%s] CC %s page %d: +%d (total=%d)", domain, cid, page, got, len(urls))
            time.sleep(interval + random.uniform(0, jitter))

    write_text(out, "\n".join(sorted(urls)) + ("\n" if urls else ""))
    log.info("[%s] Common Crawl: %d urls -> %s", domain, len(urls), out.name)
    return out


def _warc_extract_payload(gzip_bytes: bytes) -> tuple[str, bytes]:
    try:
        with gzip.GzipFile(fileobj=io.BytesIO(gzip_bytes)) as gz:
            raw = gz.read()
    except Exception:
        return "", b""

    sep = raw.find(b"\r\n\r\n")
    if sep == -1:
        return "", b""
    warc_headers = raw[:sep]
    rest = raw[sep+4:]

    if rest.startswith(b"HTTP/"):
        hsep = rest.find(b"\r\n\r\n")
        if hsep == -1:
            return "", b""
        http_headers = rest[:hsep].decode("iso-8859-1", "ignore")
        body = rest[hsep+4:]
        mime_hint = ""
        for ln in http_headers.split("\r\n"):
            if ln.lower().startswith("content-type:"):
                mime_hint = ln.split(":",1)[1].strip().split(";")[0].lower()
                break
        return mime_hint, body
    return "", rest


def _cc_period_key(ts: str, mode: str) -> str:
    y, m = ts[:4], ts[4:6]
    d = ts[6:8] if len(ts) >= 8 else "01"
    if mode == "day":
        return f"{y}-{m}-{d}"
    if mode == "month":
        return f"{y}-{m}"
    return y


def fetch_commoncrawl_bodies_for_domain(
    domain: str,
    ddir: Path,
    *,
    collections: Optional[str],
    server_url: str = "https://index.commoncrawl.org",
    cdx_from: str = "",
    cdx_to: str = "",
    period: str = "month",          # day|month|year
    max_per_path: int = 2,
    mime_allow: Optional[set[str]] = None,
    max_bytes: int = 3*1024*1024,   # cap saved body size
    qps: float = 1.0,
    timeout: int = 25,
    retries: int = 2,
) -> int:
    """
    Save HTML/JS/CSS/JSON bodies from CC into <ddir>/cc_bodies/ with meta.jsonl.
    """
    mime_allow = mime_allow or {
        "text/html","application/xhtml+xml",
        "application/javascript","text/javascript",
        "text/css","application/json"
    }
    if collections:
        cols = [c.strip() for c in collections.split(",") if c.strip()]
    else:
        cols = _latest_cc_main_collections(limit=3, timeout=timeout, server_url=server_url)

    hits = _cc_collect_hits(
        domain,
        collections=cols,
        server_url=server_url,
        max_pages=min(10, getattr(sys.modules[__name__], "DEFAULT_CC_MAX_PAGES", 5)) if False else 5,
        rps=qps,
        timeout=timeout,
        retries=retries,
        cdx_from=cdx_from,
        cdx_to=cdx_to,
        mime_allow=mime_allow,
    )

    buckets: dict[str, dict[str, list[dict]]] = {}
    def _group_key(u: str) -> str:
        p = urllib.parse.urlsplit(u)
        return f"{(p.netloc or '').lower()}{p.path or '/'}{('?' + p.query) if p.query else ''}"

    for h in hits:
        gk = _group_key(h["url"])
        pk = _cc_period_key(h.get("timestamp",""), period)
        buckets.setdefault(gk, {}).setdefault(pk, []).append(h)

    chosen: list[dict] = []
    for _, by_period in buckets.items():
        per: list[dict] = []
        for _, arr in by_period.items():
            arr.sort(key=lambda r: r.get("timestamp",""))
            per.append(arr[-1]) 
        per.sort(key=lambda r: r.get("timestamp",""), reverse=True)
        chosen.extend(per[:max_per_path])

    outdir = ddir / "cc_bodies"
    ensure_dir(outdir)
    meta_path = outdir / "meta.jsonl"
    urls_out = outdir / "urls_fetched.txt"

    fetched = 0
    interval = 1.0 / max(0.1, qps)

    with meta_path.open("a", encoding="utf-8") as mf, urls_out.open("a", encoding="utf-8") as uf:
        for h in chosen:
            data_url = f"https://data.commoncrawl.org/{h['filename']}"
            start = h["offset"]
            end   = h["offset"] + h["length"] - 1
            rng = f"bytes={start}-{end}"
            try:
                req = Request(data_url, headers={
                    "User-Agent": "ReconPhase1/CCBodies/1.0",
                    "Range": rng
                })
                with urlopen(req, timeout=timeout) as r:
                    gz = r.read()
            except Exception:
                time.sleep(interval)
                continue

            http_mime, body = _warc_extract_payload(gz)
            mm = (http_mime or h.get("mime") or "").split(";")[0].strip().lower()
            if mm and mm not in mime_allow:
                time.sleep(interval)
                continue

            if not body or len(body) > max_bytes:
                time.sleep(interval)
                continue

            ext = ".html"
            if "javascript" in mm: ext = ".js"
            elif mm == "application/json": ext = ".json"
            elif mm == "text/css": ext = ".css"

            safe = urllib.parse.quote(h["url"], safe="")[:120]
            fname = f"{h.get('timestamp','')}_{safe}{ext}"
            (outdir / fname).write_bytes(body)

            mf.write(json.dumps({
                "timestamp": h.get("timestamp",""),
                "original": h["url"],
                "cc_file": h["filename"],
                "offset": h["offset"],
                "length": h["length"],
                "mimetype": mm,
                "size": len(body),
                "range": rng,
                "data_url": data_url
            }) + "\n")
            uf.write(h["url"] + "\n")
            fetched += 1
            time.sleep(interval)

    return fetched


def _default_config_path():
    return Path(os.path.expanduser("~/.config/recon_automation/config.yml"))

def _mode_is_private(p: Path) -> bool:
    try:
        m = p.stat().st_mode
        return (m & stat.S_IRWXG) == 0 and (m & stat.S_IRWXO) == 0  
    except Exception:
        return True 

def load_kv_config(path: Optional[str]) -> dict:
    p = Path(path) if path else _default_config_path()
    if not p.exists():
        return {}
    if not _mode_is_private(p):
        print(f"WARNING: {p} permissions are too open; run: chmod 600 '{p}'", file=sys.stderr)
    try:
        text = p.read_text(encoding="utf-8", errors="ignore")
        low = p.suffix.lower()
        if low in (".yml", ".yaml"):
            data = {}
            for ln in text.splitlines():
                if not ln.strip() or ln.lstrip().startswith("#"): continue
                if ":" in ln:
                    k, v = ln.split(":", 1)
                    data[k.strip()] = v.strip().strip('"').strip("'")
            return data
        if low == ".json":
            return json.loads(text)
        if "=" in text and not "[" in text:
            data = {}
            for ln in text.splitlines():
                ln = ln.strip()
                if not ln or ln.startswith("#"): continue
                if "=" in ln:
                    k, v = ln.split("=", 1)
                    data[k.strip()] = v.strip().strip('"').strip("'")
            return data
        cfg = configparser.ConfigParser()
        cfg.read_string(text)
        data = {}
        for sect in cfg.sections():
            for k, v in cfg.items(sect):
                data[k.upper()] = v
        return data
    except Exception as e:
        print(f"WARN: failed to parse config {p}: {e}", file=sys.stderr)
        return {}

def apply_config_to_env(cfg: dict, *, mask_keys: tuple[str,...]=()):
    for k, v in cfg.items():
        if not v:
            continue
        if k in os.environ and os.environ[k]:
            continue  
        os.environ[k] = v

def _bin_exists(s: str) -> bool:
    return bool(s) and (Path(s).exists() or shutil.which(s))

def run_cmd(
    cmd: List[str],
    *,
    stdin: Optional[bytes]=None,
    timeout: Optional[int]=None,
    text: bool=True,
    cwd: Optional[str]=None,           
) -> Tuple[int, str, str]:
    try:
        cp = subprocess.run(
            cmd,
            input=stdin,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            check=False,
            cwd=cwd,  
        )
        if text:
            out = cp.stdout.decode("utf-8", errors="ignore") if isinstance(cp.stdout, (bytes, bytearray)) else str(cp.stdout)
            err = cp.stderr.decode("utf-8", errors="ignore") if isinstance(cp.stderr, (bytes, bytearray)) else str(cp.stderr)
        else:
            out, err = cp.stdout, cp.stderr
        return cp.returncode, out, err
    except subprocess.TimeoutExpired as e:
        out = e.stdout.decode("utf-8", errors="ignore") if e.stdout else ""
        err = e.stderr.decode("utf-8", errors="ignore") if e.stderr else ""
        return 124, out, (err or "") + "\n[TIMEOUT]"
    except Exception as e:
        return 127, "", f"[exec error] {e}"

def fetch_text(url: str, headers: Optional[Dict[str,str]]=None, timeout: int=30) -> str:
    req = Request(url, headers={"User-Agent":"ReconPhase1/1.0", **(headers or {})})
    try:
        with urlopen(req, timeout=timeout) as r:
            return r.read().decode("utf-8", errors="ignore")
    except Exception as e:
        log.debug("fetch_text fail %s: %s", url, e)
        return ""

def fetch_json(url: str, headers: Optional[Dict[str,str]]=None, timeout: int=30, method: str="GET", body: Optional[bytes]=None) -> Optional[dict]:
    req = Request(url, headers={"User-Agent":"ReconPhase1/1.0", **(headers or {})}, method=method, data=body)
    try:
        with urlopen(req, timeout=timeout) as r:
            return json.loads(r.read().decode("utf-8", errors="ignore"))
    except Exception as e:
        log.debug("fetch_json fail %s: %s", url, e)
        return None

def fetch_json_lines(url: str, timeout: int=30) -> List[dict]:
    txt = fetch_text(url, timeout=timeout)
    out: List[dict] = []
    for ln in (txt or "").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            obj = json.loads(ln)
            if isinstance(obj, dict):
                out.append(obj)
        except Exception:
            continue
    return out

def load_domains(fp: str) -> List[str]:
    ds: List[str] = []
    with open(fp, "r", encoding="utf-8", errors="ignore") as f:
        for ln in f:
            ln = ln.strip().lower()
            if not ln or ln.startswith("#"): continue
            ln = ln.strip().strip(".")
            ds.append(_to_ascii_idna(ln))
    return list(dict.fromkeys(ds))

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def write_text(path: Path, text: str) -> None:
    ensure_dir(path.parent)
    path.write_text(text, encoding="utf-8")

def read_lines(path: Path) -> List[str]:
    if not path.exists(): return []
    return [ln.strip() for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()]

# ---- Scope Policy (strict suffix + exact + exclude) ----
_SCOPE_POLICY = None  # set in main()

class ScopePolicy:
    """Scope model:
    - allowed_suffixes: subdomains allowed (host == suffix OR endswith .suffix)
    - allowed_exact_hosts: exact-only unless also covered by an allowed suffix
    - excluded_hosts: always out-of-scope (host == x OR endswith .x)

    scoped(host, seed) enforces BOTH:
      1) host must be in *global* scope (suffix or exact, and not excluded)
      2) host must match the current seed context:
         - if seed is covered by an allowed suffix -> host == seed or endswith .seed
         - else (exact-only seed) -> host == seed only
    """

    def __init__(self, allowed_suffixes: set[str], allowed_exact_hosts: set[str], excluded_hosts: set[str], *, strict: bool = True):
        self.allowed_suffixes = {self._norm(h) for h in (allowed_suffixes or set()) if h}
        self.allowed_exact_hosts = {self._norm(h) for h in (allowed_exact_hosts or set()) if h}
        self.excluded_hosts = {self._norm(h) for h in (excluded_hosts or set()) if h}
        self.strict = bool(strict)

    def _norm(self, host: str) -> str:
        h = _to_ascii_idna(host or "")
        h = h.strip().strip(".").lower()
        # strip port if present
        if ":" in h and not h.startswith('['):
            h = h.split(':', 1)[0]
        return h

    def is_excluded(self, host: str) -> bool:
        h = self._norm(host)
        if not h:
            return True
        for x in self.excluded_hosts:
            if h == x or h.endswith('.' + x):
                return True
        return False

    def in_allowed_suffix(self, host: str) -> bool:
        h = self._norm(host)
        for s in self.allowed_suffixes:
            if h == s or h.endswith('.' + s):
                return True
        return False

    def in_allowed_exact(self, host: str) -> bool:
        return self._norm(host) in self.allowed_exact_hosts

    def in_global_scope(self, host: str) -> bool:
        if self.is_excluded(host):
            return False
        return self.in_allowed_suffix(host) or self.in_allowed_exact(host)

    def seed_allows_subdomains(self, seed: str) -> bool:
        # If seed is covered by an allowed suffix root, subdomains are in-scope.
        # Otherwise, treat as exact-only.
        if self.is_excluded(seed):
            return False
        return self.in_allowed_suffix(seed)

    def host_in_seed(self, host: str, seed: str) -> bool:
        h = self._norm(host)
        s = self._norm(seed)
        if not h or not s:
            return False
        if not self.in_global_scope(h):
            return False
        if self.seed_allows_subdomains(s):
            return h == s or h.endswith('.' + s)
        return h == s


def seed_allows_subdomains(seed: str) -> bool:
    global _SCOPE_POLICY
    if _SCOPE_POLICY is None:
        return True
    return _SCOPE_POLICY.seed_allows_subdomains(seed)


def scoped(host: str, domain: str) -> bool:
    global _SCOPE_POLICY
    if _SCOPE_POLICY is None:
        h = _to_ascii_idna(host)
        d = _to_ascii_idna(domain)
        # strip port
        if ':' in h and not h.startswith('['):
            h = h.split(':', 1)[0]
        if ':' in d and not d.startswith('['):
            d = d.split(':', 1)[0]
        h = h.strip().strip('.').lower(); d = d.strip().strip('.').lower()
        return h == d or h.endswith('.' + d)
    return _SCOPE_POLICY.host_in_seed(host, domain)


def _seed_url_param(seed: str) -> str:
    """Return a CDX/CC url= param (with wildcard only when allowed)."""
    s = quote(seed)
    if seed_allows_subdomains(seed):
        return f"url=*.{s}/*"
    return f"url={s}/*"


def _seed_client_pattern(seed: str) -> str:
    """Return a cdx-index-client pattern (wildcard only when allowed)."""
    if seed_allows_subdomains(seed):
        return f"*.{seed}/*"
    return f"{seed}/*"

def _normalize_url(u: str) -> str:
    try:
        pu = urllib.parse.urlparse(u.strip())
        if not pu.scheme or not pu.netloc:
            return u.strip()
        scheme = pu.scheme.lower()
        host = pu.hostname.lower() if pu.hostname else ""
        port = pu.port
        if (scheme == "http" and port == 80) or (scheme == "https" and port == 443):
            netloc = host
        else:
            netloc = host if not port else f"{host}:{port}"
        path = re.sub(r"/{2,}", "/", pu.path or "/")
        return urllib.parse.urlunparse((scheme, netloc, path, "", pu.query, ""))
    except Exception:
        return u.strip()

# --------------- Archive snapshot fetch (Internet Archive bodies) ---------------

import time as _ia_time
from collections import defaultdict as _ia_defaultdict

def _cdx_query(original_url: str, cdx_from: str, cdx_to: str, qps: float) -> list[dict]:
    base = "https://web.archive.org/cdx/search/cdx"
    params = {
        "url": original_url,
        "matchType": "exact",
        "from": (cdx_from or ""),
        "to": (cdx_to or ""),
        "output": "json",
        "fl": "original,timestamp,statuscode,mimetype,length,digest",
        "filter": "statuscode:200",
    }
    u = base + "?" + urllib.parse.urlencode(params, safe=":,")
    try:
        with urlopen(Request(u, headers={"User-Agent":"ReconPhase1/ArchiveCrawl/1.0"}), timeout=20) as r:
            data = r.read().decode("utf-8", "ignore")
    except Exception:
        return []
    _ia_time.sleep(max(0.001, 1.0 / max(qps, 0.1)))
    try:
        js = json.loads(data)
    except Exception:
        return []
    if not js or not isinstance(js, list) or len(js) < 2:
        return []
    hdr = js[0]
    rows = js[1:]
    out = []
    for row in rows:
        try:
            obj = dict(zip(hdr, row))
            out.append(obj)
        except Exception:
            continue
    return out

def _normalize_path_for_grouping(original_url: str) -> str:
    p = urllib.parse.urlsplit(original_url)
    host = (p.netloc or "").lower()
    path = p.path or "/"
    q = ("?" + p.query) if p.query else ""
    return f"{host}{path}{q}"

def _period_key(ts: str, mode: str) -> str:
    y, m = ts[:4], ts[4:6]
    return f"{y}-{m}" if mode == "month" else y

def fetch_archive_bodies_for_urls(
    urls: list[str],
    outdir: Path,
    cdx_from: str = "",
    cdx_to: str = "",
    period: str = "month",
    max_per_path: int = 2,
    mime_allow: set[str] = None,
    max_bytes: int = 3*1024*1024,
    qps: float = 1.5,
    timeout: int = 20,
    retries: int = 2,
) -> int:
    mime_allow = mime_allow or {
        "text/html","application/xhtml+xml",
        "application/javascript","text/javascript",
        "text/css","application/json"
    }
    # UNIFIED OUTPUT: Use 'cc_bodies' so phase1_addons.py scans these too
    arch_dir = outdir / "cc_bodies"
    arch_dir.mkdir(parents=True, exist_ok=True)
    meta_path = arch_dir / "meta.jsonl"
    urls_out = arch_dir / "urls_fetched.txt"

    groups: dict[str, dict[str, list[dict]]] = _ia_defaultdict(lambda: _ia_defaultdict(list))
    for u in urls:
        try:
            rows = _cdx_query(u, cdx_from, cdx_to, qps)
        except Exception:
            rows = []
        for r in rows:
            mt = (r.get("mimetype") or "").split(";")[0].strip().lower()
            if mt and mt not in mime_allow:
                continue
            try:
                if int(r.get("length","0")) > max_bytes:
                    continue
            except Exception:
                pass
            gkey = _normalize_path_for_grouping(r.get("original","") or u)
            pkey = _period_key(r.get("timestamp",""), period)
            groups[gkey][pkey].append(r)

    chosen: list[dict] = []
    for _, by_period in groups.items():
        bucket: list[dict] = []
        for _, rows in by_period.items():
            rows.sort(key=lambda r: r.get("timestamp",""))
            bucket.append(rows[-1])
        bucket.sort(key=lambda r: r.get("timestamp",""), reverse=True)
        chosen.extend(bucket[:max_per_path])

    def _snap_url(ts: str, orig: str) -> str:
        return f"https://web.archive.org/web/{ts}id_/{orig}"

    fetched = 0
    with meta_path.open("a", encoding="utf-8") as mf, urls_out.open("a", encoding="utf-8") as uf:
        for r in chosen:
            ts = r.get("timestamp",""); orig = r.get("original","")
            if not ts or not orig:
                continue
            snap = _snap_url(ts, orig)
            mime = (r.get("mimetype") or "").split(";")[0].lower()
            ext = ".html"
            if "javascript" in mime: ext = ".js"
            elif mime == "application/json": ext = ".json"
            elif mime == "text/css": ext = ".css"
            safe = urllib.parse.quote(orig, safe="")[:120]
            fname = f"wayback_{ts}_{safe}{ext}"
            body_path = arch_dir / fname

            ok = False
            for attempt in range(retries+1):
                try:
                    req = Request(snap, headers={"User-Agent":"ReconPhase1/ArchiveCrawl/1.0"})
                    with urlopen(req, timeout=timeout) as rr:
                        b = rr.read()
                    if len(b) > max_bytes:
                        break
                    body_path.write_bytes(b)
                    ok = True
                    break
                except Exception:
                    _ia_time.sleep(min(2**attempt, 6))
            if not ok:
                continue

            meta = {
                "timestamp": ts,
                "original": orig,
                "snapshot_url": snap,
                "mimetype": mime,
                "size": body_path.stat().st_size,
                "source": "wayback"
            }
            mf.write(json.dumps(meta) + "\n")
            uf.write(snap + "\n")
            fetched += 1

    return fetched

# --------------- Core collectors (Wayback + GAU)

def run_wayback_and_gau(domain: str, ddir: Path, waybackurls: Optional[str], gau: Optional[str]) -> Tuple[Path, Path]:
    wayback_raw = ddir / "wayback_raw.txt"
    wayback_clean = ddir / "wayback_clean.txt"
    tmp_files: List[Path] = []
    urls: Set[str] = set()

    if _bin_exists(waybackurls):
        cmd = [waybackurls] + (['-no-subs'] if not seed_allows_subdomains(domain) else []) + [domain]
        rc, out, err = run_cmd(cmd, timeout=300)
        if rc == 0 and out:
            tmp = ddir / "_tmp_waybackurls.txt"
            write_text(tmp, out)
            tmp_files.append(tmp)
            log.info("[%s] waybackurls: %d lines", domain, len(out.splitlines()))
        else:
            log.warning("[%s] waybackurls failed rc=%s", domain, rc)

    if _bin_exists(gau):
        cmd = [gau, domain]
        rc, out, err = run_cmd(cmd, timeout=300)
        if rc == 0 and out:
            tmp = ddir / "_tmp_gau.txt"
            write_text(tmp, out)
            tmp_files.append(tmp)
            log.info("[%s] gau: %d lines", domain, len(out.splitlines()))
        else:
            log.warning("[%s] gau failed rc=%s", domain, rc) if rc else log.info("[%s] gau completed (rc=0)", domain)

    for t in tmp_files:
        for ln in read_lines(t):
            if ln.startswith("http"):
                urls.add(ln)

    write_text(wayback_raw, "\n".join(sorted(urls)) + ("\n" if urls else ""))

    drop_ext = (".png",".jpg",".jpeg",".gif",".svg",".woff",".woff2",".ttf",".eot",".mp4",".webm",".avi",
                ".mov",".zip",".gz",".bz2",".xz",".7z",".rar",".pdf",".doc",".docx",".xls",".xlsx",".ppt",".pptx")
    cleaned: Set[str] = set()
    for u in urls:
        m = re.match(r"^https?://([^/]+)/", u, flags=re.I)
        if not m: 
            continue
        host = m.group(1).lower()
        if not scoped(host, domain):
            continue
        if any(u.lower().split("?")[0].endswith(ext) for ext in drop_ext):
            continue
        cleaned.add(u)

    write_text(wayback_clean, "\n".join(sorted(cleaned)) + ("\n" if cleaned else ""))

    for t in tmp_files:
        try: t.unlink()
        except: pass

    log.info("[%s] Wayback/GAU merged: raw=%d clean=%d", domain, len(urls), len(cleaned))
    return wayback_raw, wayback_clean

def run_wayback(domain: str, ddir: Path, waybackurls: Optional[str]) -> Path:
    tmp = ddir / "_tmp_waybackurls.txt"
    if _bin_exists(waybackurls):
        rc, out, err = run_cmd([waybackurls] + (['-no-subs'] if not seed_allows_subdomains(domain) else []) + [domain], timeout=300)
        if rc == 0 and out:
            write_text(tmp, out)
            log.info("[%s] waybackurls: %d lines", domain, len(out.splitlines()))
        else:
            log.warning("[%s] waybackurls failed rc=%s", domain, rc)
            write_text(tmp, "")
    else:
        write_text(tmp, "")
        log.info("[%s] waybackurls: skipped (no CLI path)", domain)
    return tmp

def run_gau(domain: str, ddir: Path, gau: Optional[str], providers: Optional[str]) -> Path:
    tmp = ddir / "_tmp_gau.txt"
    if _bin_exists(gau):
        cmd = [gau]
        if providers:
            cmd += ["--providers", providers]
        cmd += [domain]
        rc, out, err = run_cmd(cmd, timeout=300)
        if rc == 0 and out:
            write_text(tmp, out)
            log.info("[%s] gau: %d lines (providers=%s)", domain, len(out.splitlines()), providers or "default")
        else:
            log.warning("[%s] gau failed rc=%s", domain, rc) if rc else log.info("[%s] gau completed (rc=0)", domain)
            write_text(tmp, "")
    else:
        write_text(tmp, "")
        log.info("[%s] gau: skipped (no CLI path)", domain)
    return tmp

def build_wayback_outputs(domain: str, ddir: Path, tmp_files: list[Path]) -> tuple[Path, Path]:
    wayback_raw = ddir / "wayback_raw.txt"
    wayback_clean = ddir / "wayback_clean.txt"
    urls: Set[str] = set()
    for t in tmp_files:
        for ln in read_lines(t):
            if ln.startswith("http"):
                urls.add(ln)

    write_text(wayback_raw, "\n".join(sorted(urls)) + ("\n" if urls else ""))

    drop_ext = (".png",".jpg",".jpeg",".gif",".svg",".woff",".woff2",".ttf",".eot",".mp4",".webm",".avi",
                ".mov",".zip",".gz",".bz2",".xz",".7z",".rar",".pdf",".doc",".docx",".xls",".xlsx",".ppt",".pptx")
    cleaned: Set[str] = set()
    for u in urls:
        m = re.match(r"^https?://([^/]+)/", u, flags=re.I)
        if not m: 
            continue
        host = m.group(1).lower()
        if not scoped(host, domain):
            continue
        if any(u.lower().split("?")[0].endswith(ext) for ext in drop_ext):
            continue
        cleaned.add(u)

    write_text(wayback_clean, "\n".join(sorted(cleaned)) + ("\n" if cleaned else ""))

    for t in tmp_files:
        try: t.unlink()
        except: pass

    log.info("[%s] Wayback/GAU merged: raw=%d clean=%d", domain, len(urls), len(cleaned))
    return wayback_raw, wayback_clean

def build_union_urls(domain: str, ddir: Path) -> Path:
    srcs = [
        ddir / "wayback_clean.txt",
        ddir / "wayback_deep.txt",
        ddir / "cc_urls.txt",
        ddir / "otx_urls.txt",
        ddir / "urlscan_urls.txt",
        ddir / "ia_cdx_urls.txt",
    ]
    seen: Set[str] = set()
    for fp in srcs:
        for u in read_lines(fp):
            if not (u.startswith("http://") or u.startswith("https://")):
                continue
            m = re.match(r"^https?://([^/]+)/", u, flags=re.I)
            if not m or not scoped(m.group(1).lower(), domain):
                continue
            seen.add(_normalize_url(u))
    out = ddir / "all_urls.txt"
    write_text(out, "\n".join(sorted(seen)) + ("\n" if seen else ""))
    log.info("[%s] union: %d urls -> %s", domain, len(seen), out.name)
    return out

def collect_ia_cdx(domain: str, ddir: Path, *, timeout: int = 90, cdx_from: str = "", cdx_to: str = "") -> Path:
    ensure_dir(ddir)
    out = ddir / "ia_cdx_urls.txt"
    params = [_seed_url_param(domain), "output=json", "fl=original", "filter=statuscode:200", "collapse=urlkey"]
    if cdx_from:
        params.append(f"from={cdx_from}")
    if cdx_to:
        params.append(f"to={cdx_to}")
    url = "http://web.archive.org/cdx/search/cdx?" + "&".join(params)
    log.debug("IA CDX fallback URL: %s", url)
    urls: Set[str] = set()
    try:
        txt = fetch_text(url, timeout=timeout)
        if txt:
            try:
                rows = json.loads(txt)
                for r in rows[1:]:
                    if r and isinstance(r, list) and r[0].startswith("http"):
                        u = r[0]
                        m = re.match(r"^https?://([^/]+)/", u, flags=re.I)
                        if m and scoped(m.group(1).lower(), domain):
                            urls.add(u)
            except Exception:
                for u in re.findall(r"https?://[^\s\"'<>]+", txt or ""):
                    m = re.match(r"^https?://([^/]+)/", u, flags=re.I)
                    if m and scoped(m.group(1).lower(), domain):
                        urls.add(u)
    except Exception as e:
        log.warning("[%s] IA CDX fallback failed: %s", domain, e)
    write_text(out, "\n".join(sorted(urls)) + ("\n" if urls else ""))
    log.info("[%s] IA CDX fallback: %d urls -> %s", domain, len(urls), out.name)
    return out

# --------------- Common Crawl (CC-MAIN) index puller — optional

def _latest_cc_main_collections(limit: int = 3, timeout: int = 30, server_url: str = "https://index.commoncrawl.org") -> List[str]:
    cols = []
    info = fetch_json(f"{server_url.rstrip('/')}/collinfo.json", timeout=timeout)
    try:
        if isinstance(info, list):
            for ent in info:
                cid = (ent.get("id") or "").strip()
                if cid.startswith("CC-MAIN-"):
                    cols.append(cid)
    except Exception:
        cols = []
    cols = sorted(set(cols), reverse=True)
    if not cols:
        cols = ["CC-MAIN-2025-10", "CC-MAIN-2024-50", "CC-MAIN-2024-33"]
    return cols[: max(1, limit)]

def _probe_collinfo(server_url: str, timeout: int = 10) -> bool:
    try:
        txt = fetch_text(f"{server_url.rstrip('/')}/collinfo.json", timeout=timeout)
        return bool(txt)
    except Exception:
        return False

def collect_commoncrawl_with_client(
    domain: str,
    ddir: Path,
    *,
    client_path: str,
    procs: int,
    timeout: int,
    retries: int,
    collections: Optional[str],
    server_url: str,
    extra_args: str = "",
) -> Path:
    ensure_dir(ddir)
    out = ddir / "cc_urls.txt"
    tmpdir = ddir / "_cc_tmp"
    ensure_dir(tmpdir)

    if not _probe_collinfo("https://index.commoncrawl.org", timeout=min(15, timeout)):
        log.warning("[%s] CC collinfo probe failed; falling back to native collector.", domain)
        return collect_commoncrawl(
            domain, ddir,
            max_pages=max_pages if "max_pages" in locals() else 5,
            rps=rps if "rps" in locals() else 1.0,
            timeout=timeout,
            collections=(collections or None),
            retries=retries,
            server_url="https://index.commoncrawl.org",
        )

    if client_path and os.path.isdir(client_path):
        cand = os.path.join(client_path, "cdx-index-client.py")
        if os.path.exists(cand):
            client_path = cand

    cols = [c.strip() for c in (collections.split(",") if collections else []) if c.strip()]
    if not cols:
        cols = _latest_cc_main_collections(limit=3, timeout=timeout, server_url=server_url)

    combined: List[str] = []
    for cid in cols:
        cmd = [
            sys.executable, client_path,
            "-p", str(procs),
            "--fl", "url",
            "-c", cid,
            "--timeout", str(timeout),
            "--max-retries", str(max(0, retries)),
            "-d", str(tmpdir),
        ]
        if extra_args:
            cmd += extra_args.split()

        cmd += ["-o", f"cc_urls_{cid}", "--page-size", "1000", "--timeout", str(timeout), "--max-retries", str(max(0, retries)), "--in-order", "--header", "User-Agent: ReconPhase1/1.0"]
        cmd += [_seed_client_pattern(domain)]

        rc, so, se = run_cmd(cmd, timeout=(timeout * 10))
        if rc != 0:
            log.warning("[%s] cdx-index-client failed for %s rc=%s stderr=%s", domain, cid, rc, (se or "")[:200])
            continue

        for shard in sorted(tmpdir.glob(f"cc_urls_{cid}-*")):
            combined += read_lines(shard)

    scoped_urls = []
    for u in combined:
        m = re.match(r"^https?://([^/]+)/", u, flags=re.I)
        if m and scoped(m.group(1).lower(), domain):
            scoped_urls.append(u)

    write_text(out, "\n".join(sorted(set(scoped_urls))) + ("\n" if scoped_urls else ""))
    try:
        shutil.rmtree(tmpdir)
    except Exception:
        pass

    log.info("[%s] CC via cdx-index-client: %d urls -> %s", domain, len(scoped_urls), out.name)
    return out


def _cc_filter_by_year_window(cols: list[str], cdx_from: str, cdx_to: str) -> list[str]:
    def _year(s: str) -> int:
        m = re.search(r'CC-MAIN-(\d{4})-', s)
        return int(m.group(1)) if m else 0
    y0 = int((cdx_from or "0000")[:4] or 0)
    y1 = int((cdx_to   or "9999")[:4] or 9999)
    if not y0 and not y1:
        return cols
    ylo, yhi = max(2008, y0-1), min(2100, y1+1)
    return [c for c in cols if ylo <= _year(c) <= yhi]


# --------------- Strict liveness check (httpx batched) — optional

def strict_liveness_check(
    input_file: Path,
    out_file: Path,
    httpx: str,
    *,
    httpx_threads: int = 20,
    rate_limit: int = 50,
    batch_size: int = 1000,
    per_proc_timeout: int = 900,
    request_timeout: int = 7,
    retries: int = 2
) -> int:
    urls = read_lines(input_file)
    if not urls:
        write_text(out_file, "")
        log.info("strict: no input urls.")
        return 0

    alive_acc: Set[str] = set()

    def run_batch(batch: List[str]) -> Set[str]:
        stdin_bytes = ("\n".join(batch) + "\n").encode("utf-8")
        cmd = [
            httpx, "-threads", str(httpx_threads),
            "-rate-limit", str(rate_limit),
            "-timeout", str(request_timeout),
            "-retries", str(retries),
            "-silent"
        ]
        rc, out, err = run_cmd(cmd, stdin=stdin_bytes, timeout=per_proc_timeout, text=True)
        if rc == 124:
            log.warning("httpx batch timed out after %ss; keeping partial output", per_proc_timeout)
        if out:
            out_lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
            return set(out_lines)
        return set()

    for i in range(0, len(urls), batch_size):
        batch = urls[i:i+batch_size]
        alive = run_batch(batch)
        alive_acc |= alive
        log.info("strict: batch %d/%d: alive+=%d (total %d)", i//batch_size+1, (len(urls)+batch_size-1)//batch_size, len(alive), len(alive_acc))

    write_text(out_file, "\n".join(sorted(alive_acc)) + ("\n" if alive_acc else ""))
    log.info("strict: done alive=%d", len(alive_acc))
    return len(alive_acc)

# --------------- Optional Passive add-ons (toggleable)

def ct_crtsh(domain: str, out_file: Path) -> Set[str]:
    url = f"https://crt.sh/?q={'%25.' + quote(domain) if seed_allows_subdomains(domain) else quote(domain)}&output=json"
    txt = fetch_text(url, timeout=60)
    hosts: Set[str] = set()
    try:
        arr = json.loads(txt)
        for row in arr:
            name_value = row.get("name_value","")
            for n in re.split(r"[\s,]+", name_value):
                n = n.strip().lower().strip(".")
                if n and scoped(n, domain):
                    hosts.add(n)
    except Exception:
        for n in re.findall(r"[A-Za-z0-9.-]+\." + re.escape(domain), txt):
            n = n.lower().strip(".")
            if scoped(n, domain):
                hosts.add(n)
    write_text(out_file, "\n".join(sorted(hosts)) + ("\n" if hosts else ""))
    log.info("[%s] crt.sh: %d hosts", domain, len(hosts))
    return hosts

def ct_certspotter(domain: str, out_file: Path) -> Set[str]:
    url = f"https://api.certspotter.com/v1/issuances?domain={quote(domain)}&include_subdomains={'true' if seed_allows_subdomains(domain) else 'false'}&expand=dns_names&match_wildcards=true"
    txt = fetch_text(url, timeout=60)
    hosts: Set[str] = set()
    try:
        arr = json.loads(txt)
        for row in arr:
            for n in row.get("dns_names",[]) or []:
                n = n.lower().strip(".")
                if n and scoped(n, domain):
                    hosts.add(n)
    except Exception:
        pass
    write_text(out_file, "\n".join(sorted(hosts)) + ("\n" if hosts else ""))
    log.info("[%s] certspotter: %d hosts", domain, len(hosts))
    return hosts

def github_subdomains(domain: str, ddir: Path, gh_subdomains: Optional[str]) -> Set[str]:
    out = ddir / "gh_subs.txt"

    # Accept either an explicit path via --github-subdomains OR auto-discover from PATH.
    gh_bin = (gh_subdomains or "").strip()
    if not gh_bin:
        try:
            import shutil
            gh_bin = shutil.which("github-subdomains") or ""
        except Exception:
            gh_bin = ""

    if not _bin_exists(gh_bin):
        write_text(out, "")
        log.info("[%s] github-subdomains: skipped (no CLI path)", domain)
        return set()

    env_token = os.environ.get("GITHUB_TOKEN", "")
    cmd = [gh_bin, "-d", domain]
    if env_token:
        cmd += ["-t", env_token]

    rc, stdout, stderr = run_cmd(cmd, timeout=300, cwd=str(ddir))

    if rc != 0:
        log.warning("[%s] github-subdomains failed rc=%s", domain, rc)
        write_text(out, "")
        return set()

    lines = [ln.strip().lower() for ln in stdout.splitlines() if ln.strip()]
    write_text(out, "\n".join(lines) + ("\n" if lines else ""))
    subs = {ln for ln in lines if scoped(ln, domain)}
    log.info("[%s] github-subdomains: %d", domain, len(subs))

    junk = ddir / f"{domain}.txt"
    if junk.exists():
        try:
            junk.unlink()
        except Exception:
            pass

    return subs

def registry_osint(domain: str, ddir: Path, pypi_org: Optional[str], npm_scope: Optional[str]) -> Path:
    pkg_urls = ddir / "pkg_urls.txt"
    pkg_domains = ddir / "pkg_domains.txt"
    urls: Set[str] = set()

    if pypi_org:
        txt = fetch_text(f"https://pypi.org/search/?q={quote(pypi_org)}", timeout=30)
        for m in re.finditer(r'href="(https?://[^"]+)"', txt):
            u = m.group(1)
            if domain in u:
                urls.add(u)

    if npm_scope:
        j = fetch_json(f"https://registry.npmjs.org/-/v1/search?text=scope:{quote(npm_scope)}&size=100", timeout=30)
        for obj in (j or {}).get("objects",[]) or []:
            pkg = obj.get("package", {})
            for k in ("links","publisher","maintainers"):
                v = pkg.get(k)
                if isinstance(v, dict):
                    for u in v.values():
                        if isinstance(u, str) and domain in u:
                            urls.add(u)
            for k in ("homepage","repository","bugs"):
                v = pkg.get(k)
                if isinstance(v, dict):
                    u = v.get("url","")
                    if isinstance(u, str) and domain in u:
                        urls.add(u)
                elif isinstance(v, str) and domain in v:
                    urls.add(v)

    write_text(pkg_urls, "\n".join(sorted(urls)) + ("\n" if urls else ""))
    hosts: Set[str] = set()
    for u in urls:
        m = re.match(r"^https?://([^/]+)/", u, flags=re.I)
        if m:
            h = m.group(1).lower()
            if scoped(h, domain):
                hosts.add(h)
    write_text(pkg_domains, "\n".join(sorted(hosts)) + ("\n" if hosts else ""))
    log.info("[%s] registry OSINT: urls=%d hosts=%d", domain, len(urls), len(hosts))
    return pkg_domains

def shodan_collect(domain: str, ddir: Path, api_key: Optional[str]) -> Tuple[Path, Path, Path]:
    out_jsonl = ddir / "shodan_hosts.jsonl"
    out_hosts = ddir / "shodan_hostnames.txt"
    out_ips   = ddir / "shodan_ips.txt"
    write_text(out_jsonl, ""); write_text(out_hosts, ""); write_text(out_ips, "")
    if not api_key:
        log.info("[%s] Shodan: skipped (no SHODAN_API_KEY)", domain)
        return out_jsonl, out_hosts, out_ips


    # Strict scope: never wildcard-search Shodan for exact-only seeds
    if not seed_allows_subdomains(domain):
        log.info("[%s] Shodan: skipped (exact-only seed; strict scope)", domain)
        return out_jsonl, out_hosts, out_ips
    hdr = {"Accept":"application/json"}
    page = 1
    total_hits = 0
    while page <= 5:
        url = f"https://api.shodan.io/shodan/host/search?key={api_key}&query=hostname:*.{quote(domain)}&page={page}"
        data = fetch_json(url, headers=hdr, timeout=40)
        if not data or not data.get("matches"):
            break
        hosts: Set[str] = set()
        ips: Set[str] = set()
        with out_jsonl.open("a", encoding="utf-8") as f:
            for m in data["matches"]:
                f.write(json.dumps(m) + "\n")
                for hn in (m.get("hostnames") or []):
                    hn = (hn or "").lower().strip()
                    if scoped(hn, domain):
                        hosts.add(hn)
                ip = (m.get("ip_str") or "").strip()
                if ip:
                    ips.add(ip)
        existing_hosts = set(read_lines(out_hosts))
        existing_ips   = set(read_lines(out_ips))
        write_text(out_hosts, "\n".join(sorted(existing_hosts | hosts)) + ("\n" if (existing_hosts or hosts) else ""))
        write_text(out_ips, "\n".join(sorted(existing_ips | ips)) + ("\n" if (existing_ips or ips) else ""))
        total_hits += len(data["matches"])
        page += 1
    log.info("[%s] Shodan: hits=%d", domain, total_hits)
    return out_jsonl, out_hosts, out_ips

def pdns_securitytrails(domain: str, ddir: Path, key: Optional[str]) -> Path:
    out = ddir / "pdns_hostnames.txt"
    if not key:
        if not out.exists(): write_text(out, "")
        log.info("[%s] SecurityTrails PDNS: skipped (no key)", domain)
        return out
    hdr = {"APIKEY": key}
    j = fetch_json(f"https://api.securitytrails.com/v1/domain/{quote(domain)}/subdomains", headers=hdr, timeout=40)
    subs: Set[str] = set(read_lines(out))
    for s in (j or {}).get("subdomains", []) or []:
        fq = f"{s}.{domain}".lower().strip(".")
        if scoped(fq, domain):
            subs.add(fq)
    write_text(out, "\n".join(sorted(subs)) + ("\n" if subs else ""))
    log.info("[%s] SecurityTrails PDNS: subs=%d", domain, len(subs))
    return out

_IPv4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")
_IPv6_RE = re.compile(r"^[0-9A-Fa-f:]+$")
def _is_ip(s: str) -> bool:
    return bool(_IPv4_RE.match(s) or _IPv6_RE.match(s))

def censys_lookup_ips(
    ips_file: Path,
    out_jsonl: Path,
    pat: str,
    org_id: str = "",
    batch_size: int = 50,
    rps: float = 1.0,
    max_lookups: int = 500,
) -> int:
    ips = [ln for ln in read_lines(ips_file) if _is_ip(ln)]
    ips = sorted(set(ips))[:max_lookups]
    if not ips:
        write_text(out_jsonl, "")
        log.info("Censys lookup: no IPs to query in %s", ips_file.name)
        return 0

    hdr = {
        "Authorization": f"Bearer {pat}",
        "Accept": "application/json",
        "Content-Type": "application/json",
    }
    if org_id:
        hdr["X-Organization-ID"] = org_id
    CENSYS_V3_BASE = os.environ.get("CENSYS_V3_BASE", "https://api.platform.censys.io")

    ensure_dir(out_jsonl.parent)
    written = 0
    remaining: set[str] = set(ips)
    interval = 1.0 / max(0.1, rps)

    with out_jsonl.open("w", encoding="utf-8") as f:
        for i in range(0, len(ips), batch_size):
            chunk = ips[i : i + batch_size]
            payload = json.dumps({"host_ids": chunk}).encode()
            raw = fetch_json(f"{CENSYS_V3_BASE}/v3/global/asset/host",
                             headers=hdr, timeout=30, method="POST", body=payload)
            
            val = raw
            if isinstance(val, tuple) and val:
                val = val[0]
            if val is None:
                val = []
            if isinstance(val, list):
                resources = val
            elif isinstance(val, dict):
                res = val.get("result")
                if isinstance(res, list):
                    resources = res
                elif isinstance(res, dict):
                    resources = res.get("resources") or []
                else:
                    resources = val.get("resources") or []
            else:
                resources = []

            got = 0
            for doc in resources:
                if not isinstance(doc, dict):
                    continue
                ip_val = doc.get("ip") or (doc.get("resource") or {}).get("ip")
                if not ip_val:
                    continue
                f.write(json.dumps(doc) + "\n")
                written += 1
                got += 1
                remaining.discard(ip_val)

            time.sleep(interval)

    if remaining:
        with out_jsonl.open("a", encoding="utf-8") as f:
            for ip in sorted(remaining):
                url = f"{CENSYS_V3_BASE}/v3/global/asset/host/{ip}"
                raw = fetch_json(url, headers=hdr, timeout=20)

                host_doc = None  

                if isinstance(raw, list):
                    cand = next((x for x in raw if isinstance(x, dict)), None)
                    if cand:
                        host_doc = cand.get("resource") if "resource" in cand else cand
                elif isinstance(raw, dict):
                    host_doc = ((raw.get("result") or {}).get("resource")) or raw.get("resource") or raw

                if isinstance(host_doc, dict):
                    host_doc.setdefault("ip", ip)
                    f.write(json.dumps(host_doc) + "\n")
                    written += 1

                time.sleep(interval)

    log.info("Censys v3 host-lookup: wrote %d docs from %d IPs (batch=%d, rps=%.2f) -> %s",
             written, len(ips), batch_size, rps, out_jsonl.name)
    return written

def censys_hosts(domain: str, ddir: Path, cid: Optional[str], csec: Optional[str], pat: Optional[str]=None) -> Path:
    out = ddir / "censys_hosts.jsonl"
    write_text(out, "")
    total = 0

    CENSYS_V3_BASE = os.environ.get("CENSYS_V3_BASE", "https://api.platform.censys.io")
    ORG_ID = os.environ.get("CENSYS_ORG_ID", "")

    if seed_allows_subdomains(domain):
        q_v3 = f'(host.dns.names: "*.{domain}" or cert.names: "*.{domain}")'
        q_v2_expr = f'(hostnames: "*.{domain}" OR services.tls.certificates.leaf_data.names: "*.{domain}")'
    else:
        q_v3 = f'(host.dns.names: "{domain}" or cert.names: "{domain}")'
        q_v2_expr = f'(hostnames: "{domain}" OR services.tls.certificates.leaf_data.names: "{domain}")'


    if pat:
        hdr_v3 = {
            "Authorization": f"Bearer {pat}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        if ORG_ID:
            hdr_v3["X-Organization-ID"] = ORG_ID

        cursor = None
        pages = 0
        while pages < 5:
            body_dict = {"q": q_v3, "per_page": 100}
            if cursor:
                body_dict["cursor"] = cursor
            data = fetch_json(f"{CENSYS_V3_BASE}/v3/global/search/query",
                              headers=hdr_v3, timeout=40, method="POST",
                              body=json.dumps(body_dict).encode())
            if isinstance(data, dict) and data.get("code") in (401, 403):
                log.info("[%s] Censys v3 not permitted (code=%s); will try v2.", domain, data.get("code"))
                break
            if isinstance(data, dict) and data.get("code") == 422:
                log.info("[%s] Censys v3 returned 422; will try v2 with PAT.", domain)
                break
            if isinstance(data, dict) and data.get("code") == 429:
                time.sleep(2.0)
                continue

            hits = (data or {}).get("result", {}).get("hits", []) or []
            if not hits:
                break
            with out.open("a", encoding="utf-8") as f:
                for h in hits:
                    f.write(json.dumps(h) + "\n"); total += 1

            links = (data or {}).get("result", {}).get("links", {}) or {}
            cursor = links.get("next") or ""
            pages += 1
            if not cursor:
                break

        if total > 0:
            log.info("[%s] Censys (v3 Platform) hosts: hits=%d", domain, total)
            return out
        else:
            log.debug("[%s] Censys v3 produced 0; trying v2 with PAT.", domain)

    if pat and total == 0:
        hdr_v2_pat = {
            "Authorization": f"Bearer {pat}",
            "Accept": "application/json",
            "Content-Type": "application/json",
        }
        q_v2 = q_v2_expr
        page = 1
        while page <= 5:
            body = json.dumps({"q": q_v2, "per_page": 100, "virtual_hosts": "INCLUDE", "page": page}).encode()
            data = fetch_json("https://search.censys.io/api/v2/hosts/search",
                              headers=hdr_v2_pat, timeout=40, method="POST", body=body)
            if isinstance(data, dict) and data.get("code") == 429:
                time.sleep(2.0)
                data = fetch_json("https://search.censys.io/api/v2/hosts/search",
                                  headers=hdr_v2_pat, timeout=40, method="POST", body=body)

            hits = (data or {}).get("result", {}).get("hits", []) or []
            if not hits:
                break
            with out.open("a", encoding="utf-8") as f:
                for h in hits:
                    f.write(json.dumps(h) + "\n"); total += 1
            page += 1

        if total > 0:
            log.info("[%s] Censys (v2 hosts/search via PAT) hosts: hits=%d", domain, total)
            return out

    if cid and csec and total == 0:
        import base64
        auth = base64.b64encode(f"{cid}:{csec}".encode()).decode()
        hdr_v2 = {"Authorization": f"Basic {auth}", "Accept": "application/json", "Content-Type": "application/json"}
        q_v2 = q_v2_expr
        page = 1
        while page <= 5:
            body = json.dumps({"q": q_v2, "per_page": 100, "virtual_hosts": "INCLUDE", "page": page}).encode()
            data = fetch_json("https://search.censys.io/api/v2/hosts/search",
                              headers=hdr_v2, timeout=40, method="POST", body=body)
            if isinstance(data, dict) and data.get("code") == 429:
                time.sleep(2.0)
                data = fetch_json("https://search.censys.io/api/v2/hosts/search",
                                  headers=hdr_v2, timeout=40, method="POST", body=body)

            hits = (data or {}).get("result", {}).get("hits", []) or []
            if not hits:
                break
            with out.open("a", encoding="utf-8") as f:
                for h in hits:
                    f.write(json.dumps(h) + "\n"); total += 1
            page += 1

        if total > 0:
            log.info("[%s] Censys (v2 Basic) hosts: hits=%d", domain, total)
            return out

    log.info("[%s] Censys hosts: 0 results (no eligible creds or plan limits).", domain)
    return out

def passive_subdomains(domain: str, outdir: Path, args, allowed_set: set) -> Path:
    subs_dir = outdir
    subs_file = subs_dir / "subdomains_cli.txt"
    subs_dir.mkdir(parents=True, exist_ok=True)

    acc: List[str] = []

    def _run_tool(cmd: List[str], name: str) -> None:
        try:
            rc, out, err = run_cmd(cmd, timeout=args.subs_timeout)
        except Exception as e:
            log.warning("[%s] %s failed: %s", domain, name, e)
            return

        if rc == 124:
            log.warning("[%s] %s timed out after %ss; continuing", domain, name, args.subs_timeout)
        elif rc != 0:
            log.warning("[%s] %s exited with code %s", domain, name, rc)

        if out:
            acc.extend(out.splitlines())

    if getattr(args, "enable_subdomains", "yes") == "yes":
        if getattr(args, "subfinder", None) and shutil.which(args.subfinder):
            _run_tool([args.subfinder, "-silent", "-d", domain], "subfinder")

        if getattr(args, "assetfinder", None) and shutil.which(args.assetfinder):
            _run_tool([args.assetfinder, domain], "assetfinder")

        gh_bin = getattr(args, "github_subdomains", None)
        if gh_bin and shutil.which(gh_bin) and os.getenv("GITHUB_TOKEN"):
            _run_tool([gh_bin, "-d", domain], "github-subdomains")

        if getattr(args, "amass", None) and shutil.which(args.amass):
            _run_tool([args.amass, "enum", "-passive", "-d", domain], "amass")

    hosts = [_host_from_url(s) for s in acc]
    hosts = [h for h in hosts if h and "." in h]
    hosts = _dedupe_sorted(hosts)
    hosts = _intersect_exact_hosts(hosts, allowed_set)

    subs_file.write_text("\n".join(hosts) + ("\n" if hosts else ""), encoding="utf-8")
    log.info(f"[{domain}] subdomains_cli: {len(hosts)} -> {subs_file}")
    return subs_file

def _dedupe_sorted(items):
    """Unique + sort, dropping empties."""
    return sorted({x for x in items if x})

def _intersect_exact_hosts(hosts, allowed_set):
    """If allowed_set is non-empty, keep only exact matches."""
    if not allowed_set:
        return hosts
    return [h for h in hosts if h in allowed_set]

def _host_from_url(u: str) -> str:
    """Return lowercase hostname from a URL or hostname-like string."""
    if not u:
        return ""
    u = u.strip()
    if not u:
        return ""
    if "://" not in u:
        u = "http://" + u
    try:
        from urllib.parse import urlparse
        return (urlparse(u).hostname or "").lower()
    except Exception:
        return ""

def reverse_ip_hosts(ips_file: Path, out_file: Path, api_key: str, timeout: int, domain: str,
                     rps: float = 1.5, max_queries: int = 45) -> int:
    ips = [ln for ln in read_lines(ips_file) if _IPv4_RE.match(ln)]
    ips = sorted(set(ips))
    if not ips:
        write_text(out_file, "")
        log.info("[%s] reverse-ip: no IPs to query", domain)
        return 0

    interval = 1.0 / max(0.1, rps)
    queried = 0
    results: set[str] = set()

    for ip in ips:
        if queried >= max_queries:
            log.info("[%s] reverse-ip: reached per-run cap (%d), stopping.", domain, max_queries)
            break

        url = f"https://api.hackertarget.com/reverseiplookup/?q={ip}&output=json"
        if api_key:
            url += f"&apikey={quote(api_key)}"

        txt = fetch_text(url, timeout=timeout)
        if txt and ("error" in txt.lower() or "exceeded" in txt.lower()):
            log.info("[%s] reverse-ip: provider says: %s", domain, txt.strip()[:120])
            queried += 1
            time.sleep(interval)
            continue

        hosts_this_ip: set[str] = set()
        parsed = None
        try:
            cond = bool(txt) and (txt.strip().startswith("{") or txt.strip().startswith("["))
            parsed = json.loads(txt) if cond else None
        except Exception:
            parsed = None

        if isinstance(parsed, dict) and "response" in parsed:
            for line in str(parsed.get("response") or "").splitlines():
                h = line.strip().lower().strip(".")
                if h and scoped(h, domain):
                    hosts_this_ip.add(h)
        elif isinstance(parsed, list):
            for h in parsed:
                if isinstance(h, str):
                    h = h.strip().lower().strip(".")
                    if h and scoped(h, domain):
                        hosts_this_ip.add(h)
        else:
            for line in (txt or "").splitlines():
                h = line.strip().lower().strip(".")
                if h and scoped(h, domain):
                    hosts_this_ip.add(h)

        results |= hosts_this_ip
        queried += 1
        time.sleep(interval + (0.05 if rps >= 1.0 else 0.0))

    write_text(out_file, "\n".join(sorted(results)) + ("\n" if results else ""))
    log.info("[%s] reverse-ip: %d hosts from %d IPs (queries sent=%d, rps=%.2f)", 
             domain, len(results), len(ips), queried, rps)
    return len(results)

def ipinfo_enrich(ips_file: Path, out_csv: Path, api_key: str, domain: str) -> int:
    import csv, random
    ips = [ln for ln in read_lines(ips_file) if _is_ip(ln)]
    rows = []
    base = os.environ.get("IPINFO_BASE", "https://ipinfo.io")
    for ip in ips:
        url = f"{base}/{ip}?token={quote(api_key)}" if api_key else f"{base}/{ip}"
        j = None
        for attempt in range(3):
            j = fetch_json(url, timeout=20)
            if j is not None:
                break
            time.sleep(0.5 + random.random() * 0.5)
        j = j or {}
        rows.append({
            "ip": ip,
            "org": j.get("org",""),
            "asn": (j.get("asn") or {}).get("asn","") if isinstance(j.get("asn"), dict) else "",
            "country": j.get("country",""),
            "city": j.get("city",""),
            "region": j.get("region",""),
            "hostnames": ",".join(j.get("hostnames",[]) or []),
        })
        time.sleep(0.3)
    ensure_dir(out_csv.parent)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=rows[0].keys() if rows else ["ip","org","asn","country","city","region","hostnames"])
        w.writeheader()
        for r in rows:
            w.writerow(r)
    log.info("[%s] ipinfo: enriched %d IPs -> %s", domain, len(rows), out_csv.name)
    return len(rows)

def collect_otx(domain: str, ddir: Path, *, timeout: int = 30, rps: float = 1.0) -> Path:
    out = ddir / "otx_urls.txt"
    ensure_dir(ddir)
    urls: Set[str] = set()
    page = 1
    interval = 1.0 / max(0.1, rps)

    while True:
        url = f"https://otx.alienvault.com/api/v1/indicators/domain/{quote(domain)}/url_list?limit=100&page={page}"
        data = fetch_json(url, timeout=timeout)
        if not isinstance(data, dict):
            break
        items = ((data.get("url_list") or data.get("data") or {}).get("url_list")
                 if isinstance(data.get("data"), dict) else data.get("url_list")) or []
        if not isinstance(items, list) or not items:
            break
        got = 0
        for it in items:
            u = (it.get("url") or "").strip()
            if not u.startswith(("http://", "https://")):
                continue
            m = re.match(r"^https?://([^/]+)/", u, flags=re.I)
            if not m:
                continue
            if scoped(m.group(1).lower(), domain):
                urls.add(u)
                got += 1
        log.info("[%s] OTX page %d: +%d (total=%d)", domain, page, got, len(urls))
        has_next = bool(data.get("has_next")) or bool((data.get("paging") or {}).get("next"))
        if not has_next:
            break
        page += 1
        time.sleep(interval)

    write_text(out, "\n".join(sorted(urls)) + ("\n" if urls else ""))
    log.info("[%s] OTX: %d urls -> %s", domain, len(urls), out.name)
    return out

def fetch_urlscan_artifacts(
    domain: str,
    ddir: Path,
    *,
    timeout: int = 30,
    rps: float = 1.0,
    api_key: str = "",
    download_screenshot: bool = False
) -> tuple[int,int]:
    uuid_file = ddir / "urlscan_uuids.txt"
    uuids = read_lines(uuid_file)
    if not uuids:
        return 0, 0

    headers = {"Accept": "application/json"}
    if api_key:
        headers["API-Key"] = api_key

    dom_dir = ddir / "urlscan_dom"
    res_dir = ddir / "urlscan_results"
    scn_dir = ddir / "urlscan_screens"
    ensure_dir(dom_dir); ensure_dir(res_dir); 
    if download_screenshot: ensure_dir(scn_dir)
    meta_path = dom_dir / "meta.jsonl"

    dom_n = res_n = 0
    interval = 1.0 / max(0.1, rps)

    with meta_path.open("a", encoding="utf-8") as mf:
        for uid in uuids:
            dom_url = f"https://urlscan.io/dom/{uid}/"
            try:
                req = urllib.request.Request(dom_url, headers={"User-Agent":"ReconPhase1/urlscan/1.0"})
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    dom_html = r.read()
                (dom_dir / f"{uid}.html").write_bytes(dom_html)
                dom_n += 1
            except Exception:
                pass

            rs_url = f"https://urlscan.io/api/v1/result/{uid}/"
            result_obj = None
            try:
                req = urllib.request.Request(rs_url, headers=headers)
                with urllib.request.urlopen(req, timeout=timeout) as r:
                    raw = r.read().decode("utf-8", "ignore")
                result_obj = json.loads(raw)
                (res_dir / f"{uid}.json").write_text(json.dumps(result_obj, ensure_ascii=False), encoding="utf-8")
                res_n += 1
            except Exception:
                result_obj = None

            page = (result_obj or {}).get("page") or {}
            meta = {
                "uuid": uid,
                "original": page.get("url") or "",
                "time": page.get("time") or "",
                "title": page.get("title") or "",
                "domain": domain,
                "verdicts": (result_obj or {}).get("verdicts") or {},
                "technologies": (result_obj or {}).get("technologies") or [],
            }
            mf.write(json.dumps(meta) + "\n")

            if download_screenshot:
                sc_url = f"https://urlscan.io/screenshots/{uid}.png"
                try:
                    req = urllib.request.Request(sc_url, headers={"User-Agent":"ReconPhase1/urlscan/1.0"})
                    with urllib.request.urlopen(req, timeout=timeout) as r:
                        (scn_dir / f"{uid}.png").write_bytes(r.read())
                except Exception:
                    pass

            time.sleep(interval)

    log.info("[%s] urlscan artifacts: dom=%d result=%d", domain, dom_n, res_n)
    return dom_n, res_n


def collect_urlscan(domain: str, ddir: Path, *, timeout: int = 30, rps: float = 1.0, api_key: str = "") -> Path:
    out = ddir / "urlscan_urls.txt"
    uuids_out = ddir / "urlscan_uuids.txt"
    ensure_dir(ddir)

    urls: Set[str] = set()
    uuids: Set[str] = set()
    cursor = ""
    interval = 1.0 / max(0.1, rps)

    headers = {
        "Accept": "application/json",
        "Accept-Encoding": "gzip",
        "User-Agent": "ReconPhase1/urlscan/1.0"
    }
    if api_key:
        headers["API-Key"] = api_key

    for _ in range(10):
        q = f"https://urlscan.io/api/v1/search/?q=domain:{quote(domain)}"
        if cursor:
            q += f"&cursor={quote(cursor)}"

        attempt = 0
        max_retries = 2
        data = {}
        while attempt <= max_retries:
            try:
                req = urllib.request.Request(q, headers=headers)
                with urllib.request.urlopen(req, timeout=timeout) as resp:
                    raw = resp.read()
                    if resp.headers.get("Content-Encoding","").lower() == "gzip":
                        raw = gzip.decompress(raw)
                    s = raw.decode("utf-8", "ignore")
                data = json.loads(s) if s else {}
                break
            except Exception as e:
                slp = interval * (2 ** attempt)
                log.debug("[%s] urlscan fetch fail (try %d/%d): %s; sleeping %.2fs",
                          domain, attempt+1, max_retries+1, e, slp)
                time.sleep(slp)
                attempt += 1

        results = data.get("results") or []
        if not isinstance(results, list) or not results:
            break

        got = 0
        for r in results:
            _id = (r.get("_id") or "").strip()
            if _id:
                uuids.add(_id)

            u = (((r.get("page") or {}).get("url")) or "").strip()
            if not u.startswith(("http://", "https://")):
                continue
            m = re.match(r"^https?://([^/]+)/", u, flags=re.I)
            if not m:
                continue
            if scoped(m.group(1).lower(), domain):
                urls.add(u); got += 1

        log.info("[%s] urlscan page: +%d urls (totals: urls=%d, uuids=%d)",
                 domain, got, len(urls), len(uuids))

        cursor = data.get("cursor") or data.get("next") or ""
        if not cursor:
            break

        time.sleep(interval)

    write_text(out, "\n".join(sorted(urls)) + ("\n" if urls else ""))
    write_text(uuids_out, "\n".join(sorted(uuids)) + ("\n" if uuids else ""))
    log.info("[%s] urlscan final: urls=%d, uuids=%d -> %s, %s",
             domain, len(urls), len(uuids), out.name, uuids_out.name)
    return out


# --------------- Orchestration
DEFAULT_STRICT_RATE_LIMIT   = 50
DEFAULT_STRICT_PROC_TIMEOUT = 900
DEFAULT_STRICT_BATCH_SIZE   = 1000
DEFAULT_STRICT_TIMEOUT      = 7
DEFAULT_STRICT_RETRIES      = 2
DEFAULT_HTTPX_THREADS       = 20

def process_domain(domain: str, out_root: Path, args) -> None:
    ddir = out_root / domain
    ensure_dir(ddir)
    log.info("=== %s ===", domain)

    tmp_files = []
    tmp_wayback = run_wayback(domain, ddir, args.waybackurls)
    tmp_files.append(tmp_wayback)

    cc_ok = False
    if args.enable_cc == "yes":
        try:
            if args.cc_client_path:
                collect_commoncrawl_with_client(
                    domain, ddir,
                    client_path=args.cc_client_path,
                    procs=args.cc_client_procs,
                    timeout=args.cc_timeout,
                    retries=args.cc_retries,
                    collections=(args.cc_collections or None),
                    server_url=args.cc_server_url,
                    extra_args=(args.cc_client_extra or ""),
                )
            else:
                collect_commoncrawl(
                    domain, ddir,
                    max_pages=args.cc_max_pages,
                    rps=args.cc_rps,
                    timeout=args.cc_timeout,
                    collections=(args.cc_collections or None),
                    retries=args.cc_retries,
                    server_url=args.cc_server_url,
                )
            cc_ok = (ddir / "cc_urls.txt").exists() and bool(read_lines(ddir / "cc_urls.txt"))
        except Exception as e:
            log.warning("[%s] Common Crawl failed: %s", domain, e)

    if not cc_ok and getattr(args, "enable_ia_cdx_fallback", "yes") == "yes":
        if getattr(args, "enable_wayback_cdx", "no") == "yes":
            try:
                collect_ia_cdx(domain, ddir, timeout=args.ia_cdx_timeout,
                               cdx_from=getattr(args, "cdx_from", ""), cdx_to=getattr(args, "cdx_to", ""))
            except Exception as e:
                log.warning("[%s] IA CDX fallback threw: %s", domain, e)
        else:
            log.info("[%s] IA CDX fallback: skipped (enable-wayback-cdx=no)", domain)

    otx_ok = False
    if args.enable_otx == "yes":
        try:
            collect_otx(domain, ddir, timeout=args.otx_timeout, rps=args.otx_rps)
            otx_ok = (ddir / "otx_urls.txt").exists() and bool(read_lines(ddir / "otx_urls.txt"))
        except Exception as e:
            log.warning("[%s] OTX failed: %s", domain, e)

    urlscan_ok = False
    if args.enable_urlscan == "yes":
        try:
            api_key = os.getenv("URLSCAN_API_KEY", "")
            collect_urlscan(domain, ddir, timeout=args.urlscan_timeout, rps=args.urlscan_rps, api_key=api_key)
            urlscan_ok = (ddir / "urlscan_urls.txt").exists() and bool(read_lines(ddir / "urlscan_urls.txt"))
        except Exception as e:
            log.warning("[%s] urlscan failed: %s", domain, e)

    providers_cfg = [s.strip() for s in (args.gau_providers or "").split(",") if s.strip()]
    providers_to_run = []
    if args.skip_gau_when_sources_succeed == "yes":
        for prov in providers_cfg:
            if prov == "commoncrawl" and cc_ok:
                continue
            if prov == "otx" and otx_ok:
                continue
            if prov == "urlscan" and urlscan_ok:
                continue
            if prov == "wayback":
                if (ddir / "_tmp_waybackurls.txt").exists() and bool(read_lines(ddir / "_tmp_waybackurls.txt")):
                    continue
            providers_to_run.append(prov)
    else:
        providers_to_run = providers_cfg

    if providers_to_run:
        tmp_gau = run_gau(domain, ddir, args.gau, ",".join(providers_to_run))
        tmp_files.append(tmp_gau)

    wayback_raw, wayback_clean = build_wayback_outputs(domain, ddir, tmp_files)

    # -------------------------------------------------------------
    # PASSIVE BODY DOWNLOADS (Consolidated into cc_bodies)
    # -------------------------------------------------------------
    try:
        if getattr(args, 'fetch_archive_bodies', 'no') == 'yes':
            _urls = read_lines(wayback_clean)
            if _urls:
                _mime = set([s.strip() for s in (args.archive_mime_allow or '').split(',') if s.strip()]) if getattr(args, 'archive_mime_allow', '') else None
                _fetched = fetch_archive_bodies_for_urls(
                    urls=_urls,
                    outdir=ddir,
                    cdx_from=getattr(args, 'cdx_from', ''),
                    cdx_to=getattr(args, 'cdx_to', ''),
                    period=getattr(args, 'archive_period', 'month'),
                    max_per_path=int(getattr(args, 'archive_max_per_path', 2)),
                    mime_allow=_mime,
                    max_bytes=int(getattr(args, 'archive_max_bytes', 3145728)),
                    qps=float(getattr(args, 'archive_qps', 1.5)),
                    timeout=int(getattr(args, 'archive_timeout', 20)),
                    retries=int(getattr(args, 'archive_retries', 2)),
                )
                log.info(f"[{domain}] archive-bodies (consolidated): fetched {_fetched} snapshots -> cc_bodies/")
    except Exception as _e:
        log.warning(f"[{domain}] archive-bodies: failed: {_e}")

    try:
        if getattr(args, "enable_cc_bodies", "no") == "yes":
            _mime_cc = set([s.strip() for s in (args.ccb_mime_allow or '').split(',') if s.strip()]) if getattr(args, 'ccb_mime_allow', '') else None
            fetched_cc = fetch_commoncrawl_bodies_for_domain(
                domain,
                ddir,
                collections=(args.cc_collections or None),
                server_url=args.cc_server_url,
                cdx_from=getattr(args, "cdx_from", ""),
                cdx_to=getattr(args, "cdx_to", ""),
                period=getattr(args, "ccb_period", "month"),
                max_per_path=int(getattr(args, "ccb_max_per_path", 2)),
                mime_allow=_mime_cc,
                max_bytes=int(getattr(args, "ccb_max_bytes", 3145728)),
                qps=float(getattr(args, "ccb_qps", 1.0)),
                timeout=int(getattr(args, "ccb_timeout", 25)),
                retries=int(getattr(args, "ccb_retries", 2)),
            )
            log.info(f"[{domain}] cc-bodies: fetched {fetched_cc} snapshots -> cc_bodies/")
    except Exception as _e:
        log.warning(f"[{domain}] cc-bodies: failed: {_e}")

    try:
        if getattr(args, "enable_urlscan_artifacts", "no") == "yes":
            api_key = os.getenv("URLSCAN_API_KEY", "")
            dom_n, res_n = fetch_urlscan_artifacts(
                domain, ddir,
                timeout=args.urlscan_timeout,
                rps=args.urlscan_rps,
                api_key=api_key,
                download_screenshot=(getattr(args, "urlscan_screenshot", "no") == "yes")
            )
            log.info(f"[{domain}] urlscan artifacts: dom={dom_n}, results={res_n}")
    except Exception as _e:
        log.warning(f"[{domain}] urlscan artifacts failed: {_e}")

    alive_urls = ddir / "alive_urls.txt"
    if args.passive_only == "no" and _bin_exists(args.httpx):
        strict_liveness_check(
            wayback_clean,
            alive_urls,
            args.httpx,
            httpx_threads=args.httpx_threads,
            rate_limit=args.strict_rate_limit,
            batch_size=args.strict_batch_size,
            per_proc_timeout=args.strict_proc_timeout,
            request_timeout=args.strict_timeout,
            retries=args.strict_retries
        )
    else:
        write_text(alive_urls, "")
        log.info("[%s] passive-only or httpx not set; skipping liveness.", domain)

    if args.enable_ct == "yes":
        ct1 = ct_crtsh(domain, ddir / "ct_crtsh.txt")
        ct2 = ct_certspotter(domain, ddir / "ct_certspotter.txt")
        ct_domains = ddir / "ct_domains.txt"
        write_text(ct_domains, "\n".join(sorted(ct1 | ct2)) + ("\n" if (ct1 or ct2) else ""))
        wl = ddir / "wordlists" / "subdomains.txt"
        merged = set(read_lines(wl)) | ct1 | ct2 | {domain}
        write_text(wl, "\n".join(sorted(merged)) + "\n")

    if args.enable_github_osint == "yes":
        subs = github_subdomains(domain, ddir, args.github_subdomains)
        wl = ddir / "wordlists" / "subdomains.txt"
        merged = set(read_lines(wl)) | subs | {domain}
        write_text(wl, "\n".join(sorted(merged)) + "\n")

    if args.enable_registry_osint == "yes":
        pkg_domains = registry_osint(domain, ddir, args.pypi_org or None, args.npm_scope or None)
        wl = ddir / "wordlists" / "subdomains.txt"
        merged = set(read_lines(wl)) | set(read_lines(pkg_domains)) | {domain}
        write_text(wl, "\n".join(sorted(merged)) + "\n")

    if args.enable_shodan == "yes":
        shodan_hosts, shodan_hostnames, shodan_ips = shodan_collect(domain, ddir, args.shodan_api_key)
        wl = ddir / "wordlists" / "subdomains.txt"
        merged = set(read_lines(wl)) | set(read_lines(shodan_hostnames)) | {domain}
        write_text(wl, "\n".join(sorted(merged)) + "\n")

    if args.enable_reverse_ip == "yes":
        ips_file = ddir / "shodan_ips.txt"
        if ips_file.exists():
            reverse_ip_hosts(
                ips_file,
                ddir / "reverse_ip_hosts.txt",
                args.hackertarget_key,
                args.reverse_ip_timeout,
                domain,
                rps=args.reverse_ip_rps,
                max_queries=args.reverse_ip_max_queries,
            )
            wl = ddir / "wordlists" / "subdomains.txt"
            merged = set(read_lines(wl)) | set(read_lines(ddir / "reverse_ip_hosts.txt")) | {domain}
            write_text(wl, "\n".join(sorted(merged)) + "\n")

    if args.enable_ipinfo == "yes":
        ips_file = ddir / "shodan_ips.txt"
        if ips_file.exists():
            ipinfo_enrich(ips_file, ddir / "ipinfo_enrich.csv", args.ipinfo_key, domain)

    if args.enable_censys_lookup == "yes" and args.censys_api_key:
        ips_file = ddir / "shodan_ips.txt"
        if ips_file.exists():
            censys_lookup_ips(
                ips_file,
                ddir / "censys_hosts_lookup.jsonl",
                pat=args.censys_api_key,
                org_id=args.censys_org_id,
                batch_size=50,
                rps=args.censys_rps,
                max_lookups=args.censys_max_lookups,
            )

    if args.enable_pdns == "yes":
        pdns_file = pdns_securitytrails(domain, ddir, args.securitytrails_key)
        wl = ddir / "wordlists" / "subdomains.txt"
        merged = set(read_lines(wl)) | set(read_lines(pdns_file)) | {domain}
        write_text(wl, "\n".join(sorted(merged)) + "\n")

    if args.enable_censys == "yes":
        cen_file = censys_hosts(domain, ddir, args.censys_id, args.censys_secret, pat=args.censys_api_key)

    if args.enable_wayback_cdx == "yes":
        deep = ddir / "wayback_deep.txt"
        params = [_seed_url_param(domain), "output=json", "fl=original", "filter=statuscode:200", "collapse=urlkey"]
        if getattr(args, "cdx_from", ""):
            params.append(f"from={args.cdx_from}")
        if getattr(args, "cdx_to", ""):
            params.append(f"to={args.cdx_to}")
        base = "http://web.archive.org/cdx/search/cdx?" + "&".join(params)
        log.debug("CDX URL: %s", base)
        txt = fetch_text(base, timeout=90)
        urls: Set[str] = set()
        try:
            rows = json.loads(txt)
            for r in rows[1:]:
                if r and isinstance(r, list) and r[0].startswith("http"):
                    
                    u = r[0]
                    m = re.match(r"^https?://([^/]+)/", u, flags=re.I)
                    if m and scoped(m.group(1).lower(), domain):
                        urls.add(u)
        except Exception:
            for u in re.findall(r"https?://[^\s\"'<>]+", txt or ""):
                urls.add(u)
        write_text(deep, "\n".join(sorted(urls)) + ("\n" if urls else ""))
        log.info("[%s] Wayback CDX deep: %d (from=%s to=%s)", domain, len(urls), getattr(args, "cdx_from", "") or "-", getattr(args, "cdx_to", "") or "-")

    if args.enable_subdomains == "yes":
        try:
            passive_subdomains(domain, ddir, args, allowed_set={domain})
        except Exception as e:
            logging.warning(f"[{domain}] passive_subdomains failed: {e}")

    build_union_urls(domain, ddir)
    log.info("=== %s done ===", domain)

# --------------- CLI

def parse_args():
    p = argparse.ArgumentParser(description="Phase 1 passive recon pipeline (per-domain output).")
    p.add_argument("-i","--input", required=True, help="File with allowed domains (one per line)")
    p.add_argument("-o","--outdir", required=True, help="Output root directory")
    p.add_argument("--verbose", action="store_true")

    # Strict scope policy (suffix + exact + exclude)
    p.add_argument("--strict-scope", choices=["yes","no"], default="yes", help="Enforce suffix+exact+exclude scope policy for every seed")
    p.add_argument("--allowed-suffixes-file", default="", help="File with allowed suffix roots (subdomains allowed)")
    p.add_argument("--allowed-exact-hosts-file", default="", help="File with allowed exact hosts (exact-only unless covered by an allowed suffix)")
    p.add_argument("--exclude-hosts-file", default="", help="File with explicit out-of-scope hosts to exclude (host and its subdomains)")

    p.add_argument("--passive-only", choices=["yes","no"], default="yes", help="Skip httpx liveness (no contact)")

    p.add_argument("--waybackurls", default="", help="Path to waybackurls binary")
    p.add_argument("--gau", default="", help="Path to gau binary")
    p.add_argument("--gau-providers", default="wayback,commoncrawl,otx,urlscan", help="Comma-list of gau providers")
    p.add_argument("--skip-gau-when-sources-succeed", choices=["yes","no"], default="yes", help="If yes, only run gau for providers that failed or were disabled")
    p.add_argument("--httpx", default="", help="Path to httpx binary")
    p.add_argument("--github-subdomains", dest="github_subdomains", default="", help="Path to github-subdomains CLI (optional)")

    p.add_argument("--strict-rate-limit", type=int, default=DEFAULT_STRICT_RATE_LIMIT, help="httpx -rate-limit")
    p.add_argument("--strict-proc-timeout", type=int, default=DEFAULT_STRICT_PROC_TIMEOUT, help="timeout per httpx process (seconds)")
    p.add_argument("--strict-batch-size", type=int, default=DEFAULT_STRICT_BATCH_SIZE, help="URLs per httpx process")
    p.add_argument("--strict-timeout", type=int, default=DEFAULT_STRICT_TIMEOUT, help="per-request timeout (seconds)")
    p.add_argument("--strict-retries", type=int, default=DEFAULT_STRICT_RETRIES)
    p.add_argument("--httpx-threads", type=int, default=DEFAULT_HTTPX_THREADS)

    p.add_argument("--enable-ct", choices=["yes","no"], default="no")
    p.add_argument("--enable-github-osint", choices=["yes","no"], default="no")
    p.add_argument("--enable-registry-osint", choices=["yes","no"], default="no")
    p.add_argument("--enable-shodan", choices=["yes","no"], default="no")
    p.add_argument("--enable-pdns", choices=["yes","no"], default="no")
    p.add_argument("--enable-censys", choices=["yes","no"], default="no")
    p.add_argument("--enable-wayback-cdx", choices=["yes","no"], default="no")
    p.add_argument("--enable-cc", choices=["yes","no"], default="no", help="Pull Common Crawl index into cc_urls.txt")
    p.add_argument("--enable-ia-cdx-fallback", choices=["yes","no"], default="yes", help="If CC fails/empty, fall back to Internet Archive CDX")
    p.add_argument("--ia-cdx-timeout", type=int, default=90, help="Timeout for IA CDX fallback")

    p.add_argument("--pypi-org", default="", help="Keyword/org to search on PyPI")
    p.add_argument("--npm-scope", default="", help="npm scope to enumerate")

    p.add_argument("--shodan-api-key", default=os.environ.get("SHODAN_API_KEY",""))
    p.add_argument("--securitytrails-key", default=os.environ.get("SECURITYTRAILS_KEY",""))
    p.add_argument("--censys-id", default=os.environ.get("CENSYS_API_ID",""))
    p.add_argument("--censys-secret", default=os.environ.get("CENSYS_API_SECRET",""))
    p.add_argument("--censys-api-key", default=os.environ.get("CENSYS_API_KEY",""))

    p.add_argument("--enable-subdomains", choices=["yes","no"], default="yes", help="Run passive subdomain enumerators (subfinder/amass/assetfinder)")
    p.add_argument("--subfinder", default="subfinder", help="Path to subfinder binary")
    p.add_argument("--amass", default="amass", help="Path to amass binary")
    p.add_argument("--assetfinder", default="assetfinder", help="Path to assetfinder binary")
    p.add_argument("--subs-timeout", type=int, default=600, help="Per-tool timeout seconds")

    p.add_argument("--cdx-from", default="", help="Earliest timestamp YYYYMMDDhhmmss (or YYYY or YYYYMM)")
    p.add_argument("--cdx-to",   default="", help="Latest  timestamp YYYYMMDDhhmmss (or YYYY or YYYYMM)")

    p.add_argument("--fetch-archive-bodies", choices=["yes","no"], default="no",
                   help="Download a small, time-windowed set of archived HTML/JS bodies for offline analysis")
    p.add_argument("--archive-period", choices=["month","year"], default="month",
                   help="Select newest snapshot per path per period")
    p.add_argument("--archive-max-per-path", type=int, default=2,
                   help="Hard cap of snapshots per path after period grouping")
    p.add_argument("--archive-mime-allow", default="text/html,application/xhtml+xml,application/javascript,text/javascript,text/css,application/json",
                   help="Comma-separated allowlist of MIME types to download")
    p.add_argument("--archive-max-bytes", type=int, default=3*1024*1024,
                   help="Maximum snapshot size to save (bytes)")
    p.add_argument("--archive-qps", type=float, default=1.5,
                   help="Throttle for CDX queries & downloads (queries per second)")
    p.add_argument("--archive-timeout", type=int, default=20,
                   help="Per-snapshot download timeout (seconds)")
    p.add_argument("--archive-retries", type=int, default=2,
                   help="Retries per snapshot on transient failures")
    
    p.add_argument("--enable-cc-bodies", choices=["yes","no"], default="no",
                   help="Download HTML/JS/CSS/JSON bodies from Common Crawl WARCs")
    p.add_argument("--ccb-period", choices=["day","month","year"], default="month",
                   help="Select newest snapshot per path per period for CC bodies")
    p.add_argument("--ccb-max-per-path", type=int, default=2,
                   help="Hard cap of CC snapshots per path after period grouping")
    p.add_argument("--ccb-mime-allow", default="text/html,application/xhtml+xml,application/javascript,text/javascript,text/css,application/json",
                   help="Comma-separated MIME allowlist for CC bodies")
    p.add_argument("--ccb-max-bytes", type=int, default=3*1024*1024,
                   help="Maximum CC body size to save (bytes)")
    p.add_argument("--ccb-qps", type=float, default=1.0,
                   help="Throttle for CC index queries & downloads (queries per second)")
    p.add_argument("--ccb-timeout", type=int, default=25,
                   help="Per-range request timeout (seconds)")
    p.add_argument("--ccb-retries", type=int, default=2,
                   help="Retries per CC index page on transient failures")

    p.add_argument("--enable-reverse-ip", choices=["yes","no"], default="no")
    p.add_argument("--hackertarget-key", default=os.environ.get("HACKERTARGET_API_KEY",""))
    p.add_argument("--reverse-ip-timeout", type=int, default=25)
    p.add_argument("--reverse-ip-rps", type=float, default=1.5, help="Max requests/sec to HackerTarget (free tier ~2 rps)")
    p.add_argument("--reverse-ip-max-queries", type=int, default=45, help="Max Reverse-IP queries this run (keep under free daily cap)")

    p.add_argument("--enable-ipinfo", choices=["yes","no"], default="no")
    p.add_argument("--ipinfo-key", default=os.environ.get("IPINFO_API_KEY",""))

    p.add_argument("--enable-censys-lookup", choices=["yes","no"], default="yes")
    p.add_argument("--censys-org-id", default=os.environ.get("CENSYS_ORG_ID",""))
    p.add_argument("--censys-rps", type=float, default=1.0)
    p.add_argument("--censys-max-lookups", type=int, default=500)

    p.add_argument("--cc-max-pages", type=int, default=5, help="Pages per CC-MAIN collection to fetch")
    p.add_argument("--cc-rps", type=float, default=1.0, help="Polite throttle (requests per second) across CC pages")
    p.add_argument("--cc-timeout", type=int, default=30, help="Timeout per CC request in seconds")
    p.add_argument("--cc-collections", default="", help="Comma-separated CC-MAIN IDs")
    p.add_argument("--cc-retries", type=int, default=2, help="Retries per CC page with exponential backoff")
    p.add_argument("--cc-server-url", default="https://index.commoncrawl.org",
               help="Base CDX server (default: https://index.commoncrawl.org)")
    p.add_argument("--cc-client-path", default="",
                help="Path to cdx-index-client.py (optional fallback)")
    p.add_argument("--cc-client-procs", type=int, default=4,
                help="Worker processes for cdx-index-client (optional)")
    p.add_argument("--cc-client-extra", default="",
                help="Extra args for cdx-index-client (optional, e.g. '--page-size 2000')")

    p.add_argument("--http-proxy", default="", help="Set HTTP_PROXY for provider calls (e.g., http://proxy:8080)")
    p.add_argument("--https-proxy", default="", help="Set HTTPS_PROXY for provider calls (e.g., http://proxy:8443)")

    p.add_argument("--enable-otx", choices=["yes","no"], default="no",
              help="Pull OTX URLs into otx_urls.txt")
    p.add_argument("--otx-timeout", type=int, default=30)
    p.add_argument("--otx-rps", type=float, default=1.0)

    p.add_argument("--enable-urlscan", choices=["yes","no"], default="no",
              help="Pull urlscan.io URLs into urlscan_urls.txt")
    p.add_argument("--urlscan-timeout", type=int, default=30)
    p.add_argument("--urlscan-rps", type=float, default=1.0)

    p.add_argument("--enable-urlscan-artifacts", choices=["yes","no"], default="no",
              help="Fetch DOM/result JSON/screenshot for urlscan UUIDs")
    p.add_argument("--urlscan-screenshot", choices=["yes","no"], default="no",
              help="Also download urlscan screenshot PNGs")
    
    p.add_argument("--config", default="", help="Path to YAML/JSON/.env with API keys (default: ~/.config/recon_automation/config.yml)")

    return p.parse_args()

def main():
    cfg0 = load_kv_config(None)
    apply_config_to_env(cfg0)
    if cfg0:
        log.debug("Loaded default config (~/.config/recon_automation/config.yml)")

    args = parse_args()

    if getattr(args, "config", ""):
        cfg = load_kv_config(args.config)
        apply_config_to_env(cfg)
        log.debug("Loaded config from %s (%s keys)", args.config, len(cfg or {}))

    for attr, envk in [
        ("shodan_api_key","SHODAN_API_KEY"),
        ("securitytrails_key","SECURITYTRAILS_KEY"),
        ("censys_id","CENSYS_API_ID"),
        ("censys_secret","CENSYS_API_SECRET"),
        ("censys_api_key","CENSYS_API_KEY"),
    ]:
        if not getattr(args, attr, ""):
            setattr(args, attr, os.environ.get(envk, ""))

    logging.basicConfig(
        level=(logging.DEBUG if args.verbose else logging.INFO),
        format="%(asctime)s %(levelname)s: %(message)s",
        stream=sys.stdout
    )
    out_root = Path(args.outdir).resolve()
    ensure_dir(out_root)

    # Build strict scope policy (optional but ON by default in this fork)
    global _SCOPE_POLICY
    if getattr(args, 'strict_scope', 'no') == 'yes':
        from pathlib import Path as _Path
        def _load_set(fp: str) -> set[str]:
            if not fp:
                return set()
            pth = _Path(os.path.expanduser(fp))
            if not pth.exists():
                return set()
            return set(load_domains(str(pth)))

        allowed_suffixes = _load_set(getattr(args, 'allowed_suffixes_file', ''))
        allowed_exact = _load_set(getattr(args, 'allowed_exact_hosts_file', ''))
        excluded = _load_set(getattr(args, 'exclude_hosts_file', ''))
        if not (allowed_suffixes or allowed_exact):
            log.error('strict-scope enabled but no scope files provided (need --allowed-suffixes-file and/or --allowed-exact-hosts-file)')
            sys.exit(2)
        _SCOPE_POLICY = ScopePolicy(allowed_suffixes, allowed_exact, excluded, strict=True)
        log.info('Strict scope enabled: suffixes=%d exact=%d excluded=%d', len(allowed_suffixes), len(allowed_exact), len(excluded))
    else:
        _SCOPE_POLICY = None

    domains = load_domains(args.input)
    if _SCOPE_POLICY is not None:
        kept = []
        skipped = []
        for d in domains:
            if _SCOPE_POLICY.in_global_scope(d) and not _SCOPE_POLICY.is_excluded(d):
                kept.append(d)
            else:
                skipped.append(d)
        domains = kept
        if skipped:
            log.warning('Skipping out-of-scope seeds from input: %d', len(skipped))

    if not domains:
        log.error("No domains found in %s", args.input)
        sys.exit(2)

    log.info("Loaded %d domains", len(domains))

    for dom in domains:
        try:
            process_domain(dom, out_root, args)
        except Exception as e:
            log.exception("Domain %s failed: %s", dom, e)

    log.info("All done. Outputs under %s/<domain>/", out_root)

if __name__ == "__main__":
    main()

"""
phase1_addons.py (BOTH-scope 1.5 + Passive Secrets, Tech & Cloud Permutations)
- BOTH scope: query exact seed host + any matching roots in allowlist
- Robust multi-archive: MemGator (retry) + IA CDX for exact and wildcard
- Allowlist-aware filtering (domains + subdomains) for all sources
- CC bodies: gzip-aware, HTML/JS/JSON heuristics, relative route resolution
- NEW: Passive Secret Mining (passive_secrets.json)
- NEW: Tech Profiling (archived_tech.csv)
- NEW: Cloud Bucket Permutations (cloud_permutations.txt - generation only)
"""
from __future__ import annotations
import os, sys, re, csv, json, gzip, base64
from pathlib import Path
from typing import Iterable, List, Dict, Tuple, Optional, Set
from urllib.parse import urlparse, urlunparse, parse_qsl, urlencode, urljoin

def _dbg(msg: str) -> None:
    print(f"[phase1_addons] {msg}", file=sys.stderr)

# Optional imports
try:
    import requests  # type: ignore
except Exception:
    requests = None  # type: ignore
try:
    import mmh3  # type: ignore
except Exception:
    mmh3 = None  # type: ignore
try:
    from warcio.archiveiterator import ArchiveIterator  # type: ignore
except Exception:
    ArchiveIterator = None  # type: ignore

USER_AGENT = "ReconAutomation-Phase1-Addons/1.5 (+passive_secrets; contact: security@example.com)"
SAFE_TRACK_PARAMS = ("utm_", "gclid", "fbclid", "sid", "jsessionid", "phpsessid", "sessionid")

# ----------------------------
# Secrets Patterns (Passive/High-Confidence)
# ----------------------------
PASSIVE_SECRETS_PATTERNS = [
    (re.compile(r"(?i)(?:aws|amazon).*?access.*?['\"](AKIA[A-Z0-9]{16})['\"]"), "AWS Access Key ID"),
    (re.compile(r"(?i)(?:aws|amazon).*?secret.*?['\"]([a-zA-Z0-9/+=]{40})['\"]"), "AWS Secret Access Key"),
    (re.compile(r"(?i)AIza[0-9A-Za-z-_]{35}"), "Google API Key"),
    (re.compile(r"(?i)slack_?api_?token.*?['\"](xox[baprs]-+[A-Za-z0-9-]+)['\"]"), "Slack Token"),
    (re.compile(r"(?i)stripe.*?['\"](sk_live_[0-9a-zA-Z]{24,})['\"]"), "Stripe Secret Key"),
    (re.compile(r"(?i)gh[pousr]_[A-Za-z0-9]{36}"), "GitHub Token"),
    (re.compile(r"(?i)eyJhbGciOi[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*\.[A-Za-z0-9_-]*"), "JWT Token (Potential)"),
]

# ----------------------------
# Utilities
# ----------------------------
def read_lines(path: Path) -> List[str]:
    if not path.exists():
        return []
    return [ln.strip() for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()]

def write_lines(path: Path, lines: Iterable[str]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as f:
        for ln in lines:
            f.write(ln + "\n")

def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")

def normalize_host(host: str) -> str:
    return host.strip().lower().rstrip(".")

def canonicalize_url(u: str, drop_tracking: bool = True, sort_query: bool = True) -> str:
    try:
        p = urlparse(u)
    except Exception:
        return u
    scheme = (p.scheme or "http").lower()
    netloc = p.hostname.lower() if p.hostname else ""
    if p.port and ((scheme == "http" and p.port != 80) or (scheme == "https" and p.port != 443)):
        netloc = f"{netloc}:{p.port}"
    path = re.sub(r"/{2,}", "/", p.path) or "/"
    q = []
    for k, v in parse_qsl(p.query, keep_blank_values=True):
        kl = k.lower()
        if drop_tracking and (kl.startswith(SAFE_TRACK_PARAMS) or kl in SAFE_TRACK_PARAMS):
            continue
        q.append((k, v))
    if sort_query:
        q.sort(key=lambda kv: kv[0])
    query = urlencode(q, doseq=True)
    return urlunparse((scheme, netloc, path, "", query, ""))

def collapse_numeric_ids_for_counting(u: str) -> str:
    p = urlparse(u)
    path = re.sub(r"/\d{2,}", "/{id}", p.path)
    q = []
    for k, v in parse_qsl(p.query, keep_blank_values=True):
        vv = re.sub(r"^\d{2,}$", "{id}", v)
        q.append((k, vv))
    return urlunparse((p.scheme, p.netloc, path, "", urlencode(q, doseq=True), ""))

class ScopePolicy:
    """Strict scope policy.

    - allowed_suffixes: suffix roots where subdomains are allowed (host == suffix OR endswith .suffix)
    - allowed_exact_hosts: exact hosts (no subdomains unless also covered by an allowed suffix)
    - excluded_hosts: always out-of-scope (host == x OR endswith .x)

    Note: iter(policy) yields allowed_suffixes for backwards compatibility with old code paths
    that treated the allowlist as suffix-only.
    """

    def __init__(self, allowed_suffixes, allowed_exact_hosts=None, excluded_hosts=None):
        self.allowed_suffixes = [normalize_host(x) for x in (allowed_suffixes or []) if x]
        self.allowed_exact_hosts = {normalize_host(x) for x in (allowed_exact_hosts or []) if x}
        self.excluded_hosts = {normalize_host(x) for x in (excluded_hosts or []) if x}

    def __iter__(self):
        return iter(self.allowed_suffixes)

    def is_excluded(self, host: str) -> bool:
        h = normalize_host(host or '')
        if not h:
            return True
        for x in self.excluded_hosts:
            if h == x or h.endswith('.' + x):
                return True
        return False

    def in_allowed_suffix(self, host: str) -> bool:
        h = normalize_host(host or '')
        for s in self.allowed_suffixes:
            if h == s or h.endswith('.' + s):
                return True
        return False

    def in_allowed_exact(self, host: str) -> bool:
        return normalize_host(host or '') in self.allowed_exact_hosts

    def in_global_scope(self, host: str) -> bool:
        if self.is_excluded(host):
            return False
        return self.in_allowed_suffix(host) or self.in_allowed_exact(host)

    def seed_allows_subdomains(self, seed: str) -> bool:
        # If the seed is covered by an allowed suffix root, subdomains are in-scope.
        # Otherwise treat as exact-only.
        if self.is_excluded(seed):
            return False
        return self.in_allowed_suffix(seed)


def load_scope_policy(
    *,
    allowed_suffixes_file: Path | None = None,
    allowed_exact_hosts_file: Path | None = None,
    exclude_hosts_file: Path | None = None,
    seed_fallback: str = ''
) -> ScopePolicy:
    suffixes = read_lines(allowed_suffixes_file) if (allowed_suffixes_file and allowed_suffixes_file.exists()) else []
    exacts = read_lines(allowed_exact_hosts_file) if (allowed_exact_hosts_file and allowed_exact_hosts_file.exists()) else []
    excludes = read_lines(exclude_hosts_file) if (exclude_hosts_file and exclude_hosts_file.exists()) else []

    # If no explicit allowlist was provided, fall back to suffix-seeding the current domain.
    if not suffixes and not exacts and seed_fallback:
        suffixes = [seed_fallback]

    return ScopePolicy(suffixes, exacts, excludes)


def in_scope_host(host: str, allowed: ScopePolicy) -> bool:
    # also strip port if present
    h = normalize_host((host or '').split(':', 1)[0])
    return allowed.in_global_scope(h)


def compute_archive_targets(seed_host: str, allowed: ScopePolicy) -> List[str]:
    """Exact host + any allowed suffix roots the seed belongs to."""
    h = normalize_host(seed_host)
    roots = []
    for suf in allowed.allowed_suffixes:
        s = normalize_host(suf)
        if h == s or h.endswith('.' + s):
            roots.append(s)
    return sorted(set([h] + roots))

# ----------------------------
# 1) Multi-archive union (robust)
# ----------------------------
def fetch_multiarchive_for_host(
    host_or_base: str,
    *,
    timeout_memgator: int = 60,
    timeout_cdx: int = 30,
    limit: int = 20000,
    allow_subdomains: bool = True,
) -> List[str]:
    urls: Set[str] = set()
    headers = {"User-Agent": USER_AGENT}

    def _memgator_once(seed: str) -> None:
        if requests is None:
            return
        try:
            # Encode seed so :// and / don't confuse the path parser on proxies/CDNs.
            mg_url = "https://memgator.cs.odu.edu/timemap/link/" + quote(seed, safe="")
            r = requests.get(mg_url, headers=headers, timeout=timeout_memgator)
            if r.status_code != 200:
                return

            for line in r.text.splitlines():
                for u in re.findall(r'<([^>]+)>;\s*rel="memento"', line):
                    if "web.archive.org/web/" in u:
                        try:
                            # unwrap wayback wrapper -> original URL
                            orig = u.split("web.archive.org/web/")[1].split("/", 1)[1]
                            urls.add(canonicalize_url(orig))
                        except Exception:
                            pass
        except Exception as e:
            _dbg(f"memgator error for {host_or_base}: {e}")

    # 1) MemGator seeds
    seeds = [
        f"http://{host_or_base}/",
        f"https://{host_or_base}/robots.txt",
        f"https://{host_or_base}/sitemap.xml",
    ]
    for s in seeds:
        for _ in range(2):
            _memgator_once(s)
            if len(urls) >= limit:
                break
        if len(urls) >= limit:
            break

    # 2) IA CDX
    if requests is not None:
        cdx_urls = [
            f"https://web.archive.org/cdx/search/cdx?url={host_or_base}/*&output=json&fl=original&collapse=urlkey",
        ]
        if allow_subdomains:
            cdx_urls.append(
                f"https://web.archive.org/cdx/search/cdx?url=*.{host_or_base}/*&output=json&fl=original&collapse=urlkey"
            )

        for cdx_url in cdx_urls:
            try:
                r = requests.get(cdx_url, headers=headers, timeout=timeout_cdx)
                if r.status_code != 200:
                    _dbg(f"cdx status={r.status_code} for {cdx_url}")
                    continue
                try:
                    data = r.json()
                except Exception:
                    continue

                if isinstance(data, list):
                    for row in data[1:]:
                        if row and isinstance(row, list) and row[0]:
                            urls.add(canonicalize_url(row[0]))
            except Exception as e:
                _dbg(f"cdx fetch error for {host_or_base}: {e}")

    res = sorted(urls)[:limit]
    _dbg(f"multiarchive total urls: {len(res)} for seed {host_or_base}")
    return res

# ----------------------------
# 2) Passive DNS (Rapid7 Sonar dumps - offline)
# ----------------------------
def _iter_lines_any(fp: Path):
    opener = gzip.open if fp.suffix == ".gz" else open
    with opener(fp, "rt", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line:
                yield line

def parse_sonar_fdns(fdns_files: List[Path], base_or_root: str, *, allow_subdomains: bool = True) -> List[str]:
    out: Set[str] = set()
    suffix = normalize_host(base_or_root)
    for fp in fdns_files:
        if not fp.exists():
            continue
        for line in _iter_lines_any(fp):
            if line.startswith("{") and line.endswith("}"):
                try:
                    obj = json.loads(line)
                    name = (obj.get("name") or "").lower().rstrip(".")
                except Exception:
                    continue
            else:
                parts = [p.strip('"') for p in re.split(r",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)", line)]
                name = (parts[1] if len(parts) > 1 else "").lower().rstrip(".")
            if name and ((name == suffix) or (allow_subdomains and name.endswith("." + suffix))):
                out.add(name)
    _dbg(f"sonar fdns matched {len(out)} hosts for {base_or_root}")
    return sorted(out)

def parse_sonar_rdns(rdns_files: List[Path], base_or_root: str, *, allow_subdomains: bool = True) -> List[str]:
    return parse_sonar_fdns(rdns_files, base_or_root, allow_subdomains=allow_subdomains)

# ----------------------------
# 3) ASN/Org expansion (heuristic, offline)
# ----------------------------
def expand_asn_domains(asn_list: List[str], org_keywords: List[str], allowed: List[str]) -> List[str]:
    candidates: Set[str] = set()
    for kw in org_keywords:
        kwl = kw.lower().replace(" ", "")
        for suf in allowed:
            s = normalize_host(suf)
            candidates.add(f"{kwl}.{s}")
            candidates.add(f"cdn.{kwl}.{s}")
            candidates.add(f"dev.{kwl}.{s}")
    scoped = [d for d in candidates if in_scope_host(d, allowed)]
    _dbg(f"asn/org expansion produced {len(scoped)} candidates")
    return sorted(set(scoped))

# ----------------------------
# 4) Registry pivots (Docker Hub)
# ----------------------------
def scrape_container_registry(orgs: List[str]) -> List[str]:
    links: Set[str] = set()
    if requests is None or not orgs:
        return []
    headers = {"User-Agent": USER_AGENT}
    for org in orgs:
        try:
            page = 1
            while True:
                r = requests.get(
                    f"https://hub.docker.com/v2/repositories/{org}/?page_size=100&page={page}",
                    headers=headers, timeout=15
                )
                if r.status_code != 200:
                    break
                data = r.json()
                for res in data.get("results", []):
                    desc = (res.get("description") or "") + " "
                    full = f"{res.get('namespace','')}/{res.get('name','')}"
                    for m in re.findall(r"https?://[^\s)]+", desc):
                        links.add(canonicalize_url(m))
                    links.add(f"https://hub.docker.com/r/{full}")
                if not data.get("next"):
                    break
                page += 1
        except Exception as e:
            _dbg(f"docker hub error for {org}: {e}")
    _dbg(f"container registry links: {len(links)}")
    return sorted(links)

# ----------------------------
# 5) Abuse intel (URLHaus / PhishTank)
# ----------------------------
def fetch_urlhaus_urls(allowed: List[str]) -> List[str]:
    if requests is None:
        return []
    headers = {"User-Agent": USER_AGENT}
    out: Set[str] = set()
    try:
        r = requests.get("https://urlhaus.abuse.ch/downloads/csv_recent/", headers=headers, timeout=20)
        if r.status_code != 200:
            _dbg(f"urlhaus status={r.status_code}")
            return []
        for line in r.text.splitlines():
            if line.startswith("#") or not line.strip():
                continue
            parts = line.split(",")
            if len(parts) < 3:
                continue
            url = parts[2].strip().strip('"')
            try:
                host = (urlparse(url).hostname or "").lower()
            except Exception:
                continue
            if in_scope_host(host, allowed):
                out.add(canonicalize_url(url))
        _dbg(f"urlhaus matched {len(out)} urls (allowlist scope)")
    except Exception as e:
        _dbg(f"urlhaus error: {e}")
    return sorted(out)

def fetch_phishtank_urls(allowed: List[str]) -> List[str]:
    # Requires API key; no-op by default
    return []

# ----------------------------
# 6) CC bodies mining (gzip-aware + heuristics + relative resolution)
# ----------------------------
HTML_TOKENS = (b"<html", b"<!doctype html", b"<head", b"<body")
JS_HINTS = (b"function", b"import", b"export", b"require(", b"fetch(", b"axios.", b"XMLHttpRequest", b"$.ajax")
JSON_HINTS = (b"{", b"[", b'":', b'"}', b"]")

def looks_like_html(raw: bytes) -> bool:
    low = raw[:4096].lower()
    return any(tok in low for tok in HTML_TOKENS)

def looks_like_js(raw: bytes) -> bool:
    head = raw[:4096]
    return any(tok in head for tok in JS_HINTS)

def looks_like_json(raw: bytes) -> bool:
    head = raw[:2048].strip()
    return any(tok in head for tok in JSON_HINTS)

def _maybe_gunzip(raw: bytes) -> bytes:
    if len(raw) >= 2 and raw[0] == 0x1F and raw[1] == 0x8B:
        try:
            return gzip.decompress(raw)
        except Exception:
            return raw
    return raw

def iter_cc_bodies(cc_bodies_dir: Path):
    if not cc_bodies_dir.exists():
        return []
    for fp in cc_bodies_dir.rglob("*"):
        if fp.is_dir():
            continue
        if ArchiveIterator and fp.suffix in (".warc", ".gz", ".arc"):
            opener = gzip.open if fp.suffix == ".gz" else open
            try:
                with opener(fp, "rb") as stream:
                    for rec in ArchiveIterator(stream):
                        if rec.rec_type != "response":
                            continue
                        url = rec.rec_headers.get_header("WARC-Target-URI") or ""
                        raw = rec.content_stream().read()
                        yield url, raw
            except Exception as e:
                _dbg(f"warc read error {fp}: {e}")
                continue
        else:
            try:
                raw = fp.read_bytes()
                raw = _maybe_gunzip(raw)
            except Exception:
                continue
            url = ""
            meta = fp.with_suffix(fp.suffix + ".meta")
            if meta.exists():
                try:
                    m = json.loads(meta.read_text(encoding="utf-8", errors="ignore"))
                    url = m.get("url", "")
                except Exception:
                    url = ""
            yield url, raw

def html_title_extract(raw: bytes) -> Optional[str]:
    try:
        text = raw.decode("utf-8", errors="ignore")
    except Exception:
        return None
    m = re.search(r"<title[^>]*>(.*?)</title>", text, re.I | re.S)
    if not m:
        return None
    title = re.sub(r"\s+", " ", m.group(1)).strip()
    return title[:300]

def html_generator_extract(raw: bytes) -> Optional[str]:
    try:
        text = raw.decode("utf-8", errors="ignore")
    except Exception:
        return None
    # <meta name="generator" content="WordPress 5.8" />
    m = re.search(r"<meta\s+name=[\"']generator[\"']\s+content=[\"']([^\"']+)[\"']", text, re.I)
    if not m:
        # try swapped attributes order
        m = re.search(r"<meta\s+content=[\"']([^\"']+)[\"']\s+name=[\"']generator[\"']", text, re.I)
    if m:
        return m.group(1).strip()[:100]
    return None

def scan_text_for_secrets(text: str, source_url: str) -> List[Dict[str, str]]:
    findings = []
    for pat, desc in PASSIVE_SECRETS_PATTERNS:
        for m in pat.finditer(text):
            secret_match = m.group(0)
            if "EXAMPLE" in secret_match.upper() or "12345" in secret_match:
                continue
            findings.append({
                "type": desc,
                "match": secret_match[:150], # Truncate for display safety
                "source": source_url
            })
    return findings

def mine_secrets_from_cc(cc_bodies_dir: Path) -> List[Dict[str, str]]:
    all_findings = []
    scanned = 0
    
    for url, raw in iter_cc_bodies(cc_bodies_dir):
        scanned += 1
        try:
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            continue
            
        # Pre-filter bloom
        lower_text = text.lower()
        if not any(k in lower_text for k in ("key", "token", "secret", "auth", "akia", "aiza", "eyjh")):
            continue

        findings = scan_text_for_secrets(text, url)
        all_findings.extend(findings)

    _dbg(f"cc_secrets scanned={scanned}, findings={len(all_findings)}")
    return all_findings

ABS_URL = re.compile(r'(?:"(https?://[^"]+)"|\'(https?://[^\']+)\')', re.I)
REL_URL = re.compile(r"(?:\"(/[^\"\s?#]+(?:\?[^\"]*)?)\"|'(/[^'\s?#]+(?:\?[^']*)?)')")
FETCH_SIGS = [
    re.compile(r'fetch\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'axios\.(?:get|post|put|delete|patch)\(\s*["\']([^"\']+)["\']', re.I),
    re.compile(r'\.open\(\s*["\'](?:GET|POST|PUT|DELETE|PATCH)["\']\s*,\s*["\']([^"\']+)["\']', re.I),
]

def _normalize_rel(u: str, page_url: str) -> str:
    try:
        p = urlparse(page_url)
        if not p.scheme or not p.netloc:
            return u
        if u.startswith("/"):
            return f"{p.scheme}://{p.netloc}{u}"
        return urljoin(f"{p.scheme}://{p.netloc}{p.path or '/'}", u)
    except Exception:
        return u

def extract_favicon_and_meta_from_cc(cc_bodies_dir: Path) -> Tuple[List[Tuple[str,int]], List[Tuple[str,str]], List[Tuple[str,str]]]:
    favs: List[Tuple[str,int]] = []
    titles: List[Tuple[str,str]] = []
    techs: List[Tuple[str,str]] = []
    scanned = 0
    for url, raw in iter_cc_bodies(cc_bodies_dir):
        scanned += 1
        if looks_like_html(raw):
            t = html_title_extract(raw)
            if t:
                titles.append((url, t))
            g = html_generator_extract(raw)
            if g:
                techs.append((url, g))

        if mmh3 is not None and (url.endswith("/favicon.ico") or (len(raw) > 4 and raw[:4] == b"\x00\x00\x01\x00")):
            try:
                b64 = base64.b64encode(raw)
                h = mmh3.hash(b64)
                favs.append((url, h))
            except Exception:
                pass
    _dbg(f"cc_bodies scanned={scanned}, titles={len(titles)}, techs={len(techs)}, favicons={len(favs)}")
    return favs, titles, techs

def mine_js_routes_from_cc(cc_bodies_dir: Path, allowed: List[str]) -> List[str]:
    routes: Set[str] = set()
    scanned = 0
    for url, raw in iter_cc_bodies(cc_bodies_dir):
        scanned += 1
        try:
            text = raw.decode("utf-8", errors="ignore")
        except Exception:
            continue

        # 1) absolute URLs
        for m in ABS_URL.finditer(text):
            u = m.group(1) or m.group(2)
            host = (urlparse(u).hostname or "").lower()
            if in_scope_host(host, allowed):
                routes.add(canonicalize_url(u))

        # 2) axios/fetch/xhr (absolute or relative)
        for pat in FETCH_SIGS:
            for m in pat.finditer(text):
                u = m.group(1)
                if not u:
                    continue
                if u.startswith("http"):
                    host = (urlparse(u).hostname or "").lower()
                    if in_scope_host(host, allowed):
                        routes.add(canonicalize_url(u))
                else:
                    if url:
                        absu = _normalize_rel(u, url)
                        host = (urlparse(absu).hostname or "").lower()
                        if in_scope_host(host, allowed):
                            routes.add(canonicalize_url(absu))

        # 3) generic relative URL strings ("/api/..."), only if content looks JS/HTML/JSON-ish
        if looks_like_js(raw) or looks_like_html(raw) or looks_like_json(raw):
            for m in REL_URL.finditer(text):
                u = m.group(1) or m.group(2)
                if not u:
                    continue
                if url:
                    absu = _normalize_rel(u, url)
                    host = (urlparse(absu).hostname or "").lower()
                    if in_scope_host(host, allowed):
                        routes.add(canonicalize_url(absu))

    _dbg(f"cc_routes scanned={scanned}, matched={len(routes)}")
    return sorted(routes)

# ----------------------------
# NEW: ProjectDiscovery Chaos & CIRCL PDNS
# ----------------------------
def chaos_fetch_for_roots(
    roots: List[str],
    token: Optional[str],
    timeout: int = 20,
    cache_dir: Optional[Path] = None,
    ttl_seconds: int = 86400,
    max_retries: int = 4,
    min_sleep: float = 1.0
) -> List[str]:
    """Query ProjectDiscovery Chaos per registrable root; returns hostnames (cached + backoff)."""
    if requests is None:
        _dbg("requests not available; skipping Chaos")
        return []

    import time, random, json as _json
    hdrs = {"User-Agent": "Phase1-Addons/Chaos-1.0"}
    if token:
        hdrs["Authorization"] = token

    out: Set[str] = set()
    if cache_dir:
        cache_dir.mkdir(parents=True, exist_ok=True)

    def _cache_read(root: str) -> Optional[List[str]]:
        if not cache_dir: return None
        cf = cache_dir / f"chaos_{root.replace('.', '_')}.json"
        try:
            st = cf.stat()
            if (time.time() - st.st_mtime) <= ttl_seconds:
                data = _json.loads(cf.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    return data
        except Exception:
            pass
        return None

    def _cache_write(root: str, subs: List[str]) -> None:
        if not cache_dir: return
        cf = cache_dir / f"chaos_{root.replace('.', '_')}.json"
        try:
            cf.write_text(_json.dumps(subs), encoding="utf-8")
        except Exception:
            pass

    sess = requests.Session()
    for i, root in enumerate(roots):
        rroot = normalize_host(root)
        if not rroot or "." not in rroot:
            continue

        cached = _cache_read(rroot)
        if cached is not None:
            out.update(normalize_host(f"{s}.{rroot}") for s in cached if s)
            continue

        url = f"https://dns.projectdiscovery.io/dns/{rroot}/subdomains"
        if i > 0:
            time.sleep(min_sleep + random.random()*0.5)

        tries = 0
        while True:
            tries += 1
            try:
                resp = sess.get(url, headers=hdrs, timeout=timeout)
                code = resp.status_code
                if code == 200:
                    data = resp.json()
                    subs = data.get("subdomains", []) if isinstance(data, dict) else []
                    _cache_write(rroot, subs)
                    for s in subs or []:
                        out.add(normalize_host(f"{s}.{rroot}"))
                    break
                elif code in (429, 500, 502, 503, 504):
                    wait = (2 ** (tries-1)) + random.random()
                    _dbg(f"chaos {rroot} status={code}; retry {tries}/{max_retries} in {wait:.1f}s")
                    if tries >= max_retries:
                        break
                    time.sleep(wait)
                    continue
                else:
                    break
            except Exception as e:
                _dbg(f"chaos error {rroot}: {e}")
                if tries >= max_retries:
                    break
                time.sleep((2 ** (tries-1)) + random.random())

    _dbg(f"chaos total hosts: {len(out)}")
    return sorted(out)

def circl_pdns_for_names(names: List[str], user: Optional[str], passwd: Optional[str], timeout: int = 20) -> List[str]:
    """Query CIRCL PDNS per name; returns observed rrname hostnames."""
    if requests is None:
        _dbg("requests not available; skipping CIRCL")
        return []
    if not user or not passwd:
        _dbg("CIRCL creds not set; skipping CIRCL")
        return []
    out: Set[str] = set()
    auth = (user, passwd)
    hdrs = {"User-Agent": "Phase1-Addons/CIRCL-1.0", "Accept": "application/json"}
    for n in names:
        q = normalize_host(n)
        if not q:
            continue
        url = f"https://www.circl.lu/pdns/query/{q}"
        try:
            resp = requests.get(url, headers=hdrs, auth=auth, timeout=timeout)
            if resp.status_code != 200:
                continue
            data = resp.json()
            if isinstance(data, list):
                for row in data:
                    rr = normalize_host(str(row.get("rrname", "")))
                    if rr:
                        out.add(rr)
        except Exception:
            pass
    _dbg(f"circl total hosts: {len(out)}")
    return sorted(out)

# ----------------------------
# 7) Dedupe & quality gates + scoring
# ----------------------------
def dedupe_and_stats(urls_by_source: Dict[str, List[str]]) -> Tuple[List[str], Dict[str, object]]:
    stats = {"sources": {}, "union_count": 0, "after_collapse_count": 0}
    union: Set[str] = set()
    for src, urls in urls_by_source.items():
        can = [canonicalize_url(u) for u in urls]
        stats["sources"][src] = {"raw": len(urls), "canonical": len(set(can))}
        union.update(can)
    union_list = sorted(union)
    collapsed = [collapse_numeric_ids_for_counting(u) for u in union_list]
    stats["union_count"] = len(union_list)
    stats["after_collapse_count"] = len(set(collapsed))
    return union_list, stats

def score_urls(union_urls: List[str], multi_source_index: Set[str], archived_titles_map: Dict[str, str]) -> Dict[str, int]:
    score: Dict[str, int] = {}
    for u in union_urls:
        s = 0
        if u in multi_source_index:
            s += 2
        title = (archived_titles_map.get(u, "") or "").lower()
        if any(k in title for k in ("admin", "manage", "swagger", "openapi")):
            s += 1
        score[u] = s
    return score

# ----------------------------
# 7.5) Passive Cloud Permutations (Offline/Gen-only)
# ----------------------------
def generate_cloud_permutations(domain: str) -> List[str]:
    """
    Generates a list of likely cloud bucket names for the given domain.
    Does NOT perform DNS resolution to remain strictly passive.
    """
    stems = [domain.split('.')[0]]
    if "www." in domain:
        stems.append(domain.replace("www.", "").split('.')[0])
    
    stems = sorted(list(set(s for s in stems if len(s) > 3)))
    
    keywords = ["dev", "test", "prod", "staging", "assets", "static", "public", "backup", "logs"]
    seps = ["-", ".", ""]
    
    candidates = set()
    for s in stems:
        candidates.add(s)
        for kw in keywords:
            for sep in seps:
                candidates.add(f"{s}{sep}{kw}")
                candidates.add(f"{kw}{sep}{s}")
    
    # Expand to full hostnames for common providers
    final_hosts = []
    providers = [
        ".s3.amazonaws.com",
        ".storage.googleapis.com",
        ".blob.core.windows.net"
    ]
    for c in candidates:
        for p in providers:
            final_hosts.append(c + p)
            
    return sorted(final_hosts)

# ----------------------------
# Orchestrator
# ----------------------------
def run_phase1_addons(
    domain: str,
    output_root: Path,
    allowed_suffixes_file: Path | None = None,
    allowed_exact_hosts_file: Path | None = None,
    exclude_hosts_file: Path | None = None,
    allowed_domains_file: Path | None = None,
    sonar_fdns_paths: Optional[List[str]] = None,
    sonar_rdns_paths: Optional[List[str]] = None,
    cc_bodies_dir: Optional[str] = None,
    org_keywords: Optional[List[str]] = None,
    container_orgs: Optional[List[str]] = None,
    enable_network: bool = True,
) -> Dict[str, str]:
    out_paths: Dict[str, str] = {}
    output_root.mkdir(parents=True, exist_ok=True)

    # Build strict scope policy (suffix roots + exact hosts + exclusions).
    # If only legacy allowed_domains_file is provided, treat it as suffix-roots-only for safety.
    if allowed_suffixes_file or allowed_exact_hosts_file or exclude_hosts_file:
        allowed = load_scope_policy(
            allowed_suffixes_file=allowed_suffixes_file,
            allowed_exact_hosts_file=allowed_exact_hosts_file,
            exclude_hosts_file=exclude_hosts_file,
            seed_fallback=domain
        )
    elif allowed_domains_file and allowed_domains_file.exists():
        allowed = load_scope_policy(allowed_suffixes_file=allowed_domains_file, seed_fallback=domain)
    else:
        allowed = load_scope_policy(seed_fallback=domain)
    _dbg(f"domain={domain} allowed={allowed} network={enable_network}")

    # 1) Multi-archive (BOTH: exact host + allowed roots)
    targets = compute_archive_targets(domain, allowed)
    collected: List[str] = []
    if enable_network:
        for t in targets:
            collected += fetch_multiarchive_for_host(t, allow_subdomains=allowed.seed_allows_subdomains(t))
    wayback_multi = sorted(set(collected))
    write_lines(output_root / "wayback_multiarch.txt", wayback_multi)
    out_paths["wayback_multiarch.txt"] = (output_root / "wayback_multiarch.txt").as_posix()

    # 2) Passive DNS (optional offline)
    fdns_list = [Path(p) for p in (sonar_fdns_paths or [])]
    rdns_list = [Path(p) for p in (sonar_rdns_paths or [])]
    pdns_fdns: List[str] = []
    pdns_rdns: List[str] = []
    if fdns_list:
        for t in targets:
            pdns_fdns.extend(parse_sonar_fdns(fdns_list, t, allow_subdomains=allowed.seed_allows_subdomains(t)))
        pdns_fdns = sorted(set(pdns_fdns))
    if rdns_list:
        for t in targets:
            pdns_rdns.extend(parse_sonar_rdns(rdns_list, t, allow_subdomains=allowed.seed_allows_subdomains(t)))
        pdns_rdns = sorted(set(pdns_rdns))
    write_lines(output_root / "pdns_fdns.txt", pdns_fdns)
    write_lines(output_root / "pdns_rdns.txt", pdns_rdns)
    out_paths["pdns_fdns.txt"] = (output_root / "pdns_fdns.txt").as_posix()
    out_paths["pdns_rdns.txt"] = (output_root / "pdns_rdns.txt").as_posix()

    # 3) ASN/Org expansion (heuristic)
    asn_domains = expand_asn_domains([], org_keywords or [], allowed)
    write_lines(output_root / "asn_domains.txt", asn_domains)
    out_paths["asn_domains.txt"] = (output_root / "asn_domains.txt").as_posix()

    # 4) Registry pivots
    containers_urls = scrape_container_registry(container_orgs or []) if enable_network else []
    write_lines(output_root / "containers_urls.txt", containers_urls)
    out_paths["containers_urls.txt"] = (output_root / "containers_urls.txt").as_posix()

    # 5) Abuse intel (allowlist-aware)
    urlhaus = fetch_urlhaus_urls(allowed) if enable_network else []
    write_lines(output_root / "urlhaus_urls.txt", urlhaus)
    out_paths["urlhaus_urls.txt"] = (output_root / "urlhaus_urls.txt").as_posix()
    write_lines(output_root / "phishtank_urls.txt", [])
    out_paths["phishtank_urls.txt"] = (output_root / "phishtank_urls.txt").as_posix()

    # 5.5) NEW: ProjectDiscovery Chaos & CIRCL PDNS
    chaos_hosts: List[str] = []
    circl_hosts: List[str] = []
    if enable_network:
        roots = sorted({".".join(a.split(".")[-2:]) for a in allowed.allowed_suffixes if "." in a})
        chaos_key = (os.environ.get("CHAOS_KEY") or os.environ.get("CHAOS_TOKEN") or "").strip() or None
        if chaos_key:
            chaos_hosts = [
                h for h in chaos_fetch_for_roots(
                    roots, chaos_key, timeout=20, cache_dir=(output_root / ".cache_chaos")
                )
                if in_scope_host(h, allowed)
            ]

        circl_user = (os.environ.get("CIRCL_PDNS_USER") or "").strip()
        circl_pass = (os.environ.get("CIRCL_PDNS_PASS") or "").strip()
        if circl_user and circl_pass:
            circl_res = circl_pdns_for_names(allowed, circl_user, circl_pass)
            circl_hosts = [h for h in circl_res if in_scope_host(h, allowed)]

    write_lines(output_root / "chaos_subdomains.txt", chaos_hosts)
    write_lines(output_root / "circl_pdns.txt", circl_hosts)
    out_paths["chaos_subdomains.txt"] = (output_root / "chaos_subdomains.txt").as_posix()
    out_paths["circl_pdns.txt"] = (output_root / "circl_pdns.txt").as_posix()

    # 6) CC bodies (offline allowlist-aware routes + SECRETS + TECH)
    if cc_bodies_dir:
        cc_dir = Path(cc_bodies_dir)
        
        # Extractor for Favicons, Titles, and Tech (Generator)
        favs, titles, techs = extract_favicon_and_meta_from_cc(cc_dir)
        
        # Write Favicons
        fav_path = output_root / "archived_favicon_hashes.csv"
        with fav_path.open("w", encoding="utf-8", newline="") as f:
            w = csv.writer(f); w.writerow(["url","mmh3_hash"])
            for u, h in favs: w.writerow([u, h])
        out_paths["archived_favicon_hashes.csv"] = fav_path.as_posix()

        # Write Titles
        title_path = output_root / "archived_titles.csv"
        with title_path.open("w", encoding="utf-8", newline="") as f:
            w = csv.writer(f); w.writerow(["url","title"])
            for u, t in titles: w.writerow([u, t])
        out_paths["archived_titles.csv"] = title_path.as_posix()
        
        # Write Tech (New)
        tech_path = output_root / "archived_tech.csv"
        with tech_path.open("w", encoding="utf-8", newline="") as f:
            w = csv.writer(f); w.writerow(["url","generator_tag"])
            for u, t in techs: w.writerow([u, t])
        out_paths["archived_tech.csv"] = tech_path.as_posix()

        # Mine Secrets (New)
        secrets = mine_secrets_from_cc(cc_dir)
        secrets_path = output_root / "passive_secrets.json"
        write_json(secrets_path, secrets)
        out_paths["passive_secrets.json"] = secrets_path.as_posix()

        # Mine Routes (Existing)
        routes = mine_js_routes_from_cc(cc_dir, allowed)
        write_lines(output_root / "cc_routes.txt", routes)
        out_paths["cc_routes.txt"] = (output_root / "cc_routes.txt").as_posix()
    else:
        _dbg("no cc_bodies_dir provided or missing; skipping CC offline mining")
        
    # 6.5) Cloud Permutations (Strictly Passive - generation only)
    cloud_perms = generate_cloud_permutations(domain)
    write_lines(output_root / "cloud_permutations.txt", cloud_perms)
    out_paths["cloud_permutations.txt"] = (output_root / "cloud_permutations.txt").as_posix()

    # 7) Dedupe & stats (include cc_routes if present)
    sources = {
        "wayback_multiarch": wayback_multi,
        "urlhaus": urlhaus,
        "containers": containers_urls,
    }
    cc_routes_path = output_root / "cc_routes.txt"
    if cc_routes_path.exists():
        sources["cc_routes"] = read_lines(cc_routes_path)

    union_list, stats = dedupe_and_stats(sources)

    # host-only source counts (Chaos/CIRCL) → into stats
    stats.setdefault("host_sources", {}).update({
        "chaos_subdomains": len(set(chaos_hosts)),
        "circl_pdns": len(set(circl_hosts)),
    })

    # final safety: keep only in-scope URLs
    def _host_of(u: str) -> str:
        try:
            return (urlparse(u).hostname or "").lower().rstrip(".")
        except Exception:
            return ""

    union_list = [u for u in union_list if in_scope_host(_host_of(u), allowed)]

    write_lines(output_root / "multiaddons_union.txt", union_list)
    write_json(output_root / "phase1_dedupe_stats.json", stats)
    out_paths["multiaddons_union.txt"] = (output_root / "multiaddons_union.txt").as_posix()
    out_paths["phase1_dedupe_stats.json"] = (output_root / "phase1_dedupe_stats.json").as_posix()

    # scoring (basic)
    archived_titles_map: Dict[str, str] = {}
    at = output_root / "archived_titles.csv"
    if at.exists():
        try:
            for row in csv.DictReader(at.open("r", encoding="utf-8")):
                archived_titles_map[row.get("url","")] = row.get("title","")
        except Exception:
            pass
    multi_source_index: Set[str] = set()
    scores = score_urls(union_list, multi_source_index, archived_titles_map)
    write_json(output_root / "phase1_scores.json", scores)
    out_paths["phase1_scores.json"] = (output_root / "phase1_scores.json").as_posix()

    return out_paths
#!/usr/bin/env python3
"""
Expand IP seeds to hostnames (domains) for Phase-1 inputs without touching your pipeline.

Features (each optional; automatically enabled if the env var is present):
  - PTR reverse DNS (dnspython if available, else socket.gethostbyaddr)
  - Shodan reverse:        env SHODAN_API_KEY
  - SecurityTrails reverse env SECURITYTRAILS_KEY
  - Censys hosts API       env CENSYS_API_KEY  OR  (CENSYS_API_ID + CENSYS_API_SECRET)
  - IPinfo PTR/hostname    env IPINFO_API_KEY
  - Optional FCrDNS verify for PTR-derived hosts: --verify-fcrdns yes
  - Optional DOMAIN ENUM for non-IP tokens: --enum-domains yes (subfinder/assetfinder/amass)
  - Debug/telemetry: --log-level, --log-every, --stats-json

Usage:
  python3 expand_ips_to_domains_fcrdns_api_debug.py --in seeds.txt --out hosts.txt \
      --workers 32 --timeout 2.5 --resolvers 1.1.1.1,8.8.8.8 --emit-map ip_to_host_map.csv \
      --verify-fcrdns yes --enum-domains yes --enum-tools subfinder,amass \
      --log-level DEBUG --log-every 10 --stats-json run_stats.json

Exit codes:
  0 = success (even if some inputs yield nothing)
  2 = output set is empty (no hostnames produced)
"""

from __future__ import annotations
import argparse, concurrent.futures as cf, ipaddress, json, os, re, socket, sys, time, logging, subprocess, tempfile
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple, Dict, Any

# ---------------- logging ----------------
log = logging.getLogger("expand_ips_to_domains")

def _setup_logging(level: str) -> None:
    lvl = getattr(logging, level.upper(), logging.INFO)
    h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("[%(asctime)s] %(levelname)s: %(message)s"))
    log.addHandler(h)
    log.setLevel(lvl)

# ---------------- util ----------------

def read_lines(p: Path) -> List[str]:
    if not p.exists():
        return []
    out = []
    for ln in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = ln.strip()
        if not s or s.startswith("#"):
            continue
        out.append(s)
    return out

def write_lines(p: Path, lines: Iterable[str]) -> None:
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")

def is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

_HOST_RE = re.compile(r"(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z0-9\-]{2,63}\.?$", re.I)

def to_ascii_idna(host: str) -> str:
    h = host.strip().strip(".")
    if not h:
        return h
    try:
        return h.encode("idna").decode("ascii").lower()
    except Exception:
        return h.lower()

def norm_host(h: str) -> Optional[str]:
    """Return normalized hostname if it looks like a domain/hostname, else None."""
    h = to_ascii_idna(h)
    if not h:
        return None
    # keep trailing dot away; ensure it has a dot (domain-ish)
    if _HOST_RE.match(h + "."):
        return h
    return None

def uniq(seq: Iterable[str]) -> List[str]:
    seen = set()
    out = []
    for x in seq:
        if x not in seen:
            seen.add(x)
            out.append(x)
    return out

def which(cmd: str) -> Optional[str]:
    from shutil import which as _which
    return _which(cmd)

# ---------------- PTR reverse ----------------

class PTRResolver:
    def __init__(self, resolvers: Optional[List[str]], timeout: float):
        self.timeout = timeout
        self.has_dnspython = False
        self.resolver = None
        try:
            import dns.resolver, dns.reversename
            self.dns = sys.modules["dns"]
            self.has_dnspython = True
            self.resolver = self.dns.resolver.Resolver(configure=True)
            if resolvers:
                self.resolver.nameservers = resolvers
            self.resolver.lifetime = timeout
            self.resolver.timeout = timeout
        except Exception:
            # Fallback to socket.gethostbyaddr
            self.dns = None

    def ptr(self, ip: str) -> List[str]:
        names: List[str] = []
        if self.has_dnspython:
            try:
                rev = self.dns.reversename.from_address(ip)
                ans = self.resolver.resolve(rev, "PTR", lifetime=self.timeout)
                for r in ans:
                    name = str(r.target).rstrip(".")
                    if name:
                        names.append(name)
            except Exception as e:
                log.debug(f"[PTR/dnspython] {ip} -> error: {e}")
        else:
            try:
                socket.setdefaulttimeout(self.timeout)
                name, aliases, _ = socket.gethostbyaddr(ip)
                cand = [name] + list(aliases)
                for c in cand:
                    c = c.rstrip(".")
                    if c:
                        names.append(c)
            except Exception as e:
                log.debug(f"[PTR/socket] {ip} -> error: {e}")
        out = []
        seen = set()
        for n in names:
            nh = norm_host(n)
            if nh and nh not in seen:
                seen.add(nh)
                out.append(nh)
        return out

# ---------------- Forward resolve for FCrDNS ----------------

def resolve_addrs(host: str, resolvers: Optional[List[str]], timeout: float) -> Set[str]:
    """Resolve A/AAAA; prefer dnspython, then socket.getaddrinfo. Return stringified IPs."""
    addrs: Set[str] = set()
    # dnspython if available
    try:
        import dns.resolver as _r
        r = _r.Resolver(configure=True)
        if resolvers:
            r.nameservers = resolvers
        r.timeout = timeout
        r.lifetime = timeout
        for rr in ("A", "AAAA"):
            try:
                for rdata in r.resolve(host, rr, lifetime=timeout):
                    addr = getattr(rdata, "address", None)
                    if addr:
                        addrs.add(str(addr))
            except Exception as e:
                log.debug(f"[Resolve/dnspython] {host} {rr} -> error: {e}")
    except Exception:
        pass
    # socket fallback / augmentation
    try:
        for fam in (socket.AF_INET, socket.AF_INET6):
            try:
                infos = socket.getaddrinfo(host, None, fam, 0, 0, socket.AI_ADDRCONFIG)
                for _f,_t,_p,_c,sa in infos:
                    if sa and sa[0]:
                        addrs.add(sa[0])
            except Exception as e:
                log.debug(f"[Resolve/socket] {host} fam={fam} -> error: {e}")
    except Exception as e:
        log.debug(f"[Resolve/socket] {host} -> error: {e}")
    # normalize IP strings
    out: Set[str] = set()
    for a in addrs:
        try:
            out.add(str(ipaddress.ip_address(a)))
        except Exception:
            pass
    return out

# ---------------- HTTP helpers ----------------

def _http_json(url: str, headers: Dict[str,str] | None, timeout: float) -> Any:
    import urllib.request, urllib.error
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "recon/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ct = resp.headers.get("Content-Type","")
            data = resp.read()
            if "application/json" in ct or data.startswith(b"{") or data.startswith(b"["):
                return json.loads(data.decode("utf-8", "ignore"))
            # fallback: try json anyway
            return json.loads(data.decode("utf-8", "ignore"))
    except Exception as e:
        log.debug(f"[HTTP] {url} -> error: {e}")
        return None

# ---------------- Shodan reverse ----------------

def shodan_reverse(ip: str, api_key: Optional[str], timeout: float) -> List[str]:
    if not api_key:
        return []
    url = f"https://api.shodan.io/dns/reverse?ips={ip}&key={api_key}"
    data = _http_json(url, headers=None, timeout=timeout)
    hosts: List[str] = []
    try:
        if isinstance(data, dict):
            val = data.get(ip)
            if isinstance(val, list):
                hosts = [str(x) for x in val]
        elif isinstance(data, list):
            hosts = [str(x) for x in data]
    except Exception:
        pass
    out = []
    seen = set()
    for h in hosts:
        nh = norm_host(h)
        if nh and nh not in seen:
            seen.add(nh)
            out.append(nh)
    if out:
        log.debug(f"[Shodan] {ip} -> {len(out)} hosts")
    return out

# ---------------- SecurityTrails reverse IP ----------------

def securitytrails_domains(ip: str, key: Optional[str], timeout: float) -> List[str]:
    if not key:
        return []
    headers = {"User-Agent":"recon/1.0", "APIKEY": key}
    url = f"https://api.securitytrails.com/v1/ips/{ip}/domains"
    data = _http_json(url, headers=headers, timeout=timeout)
    out: List[str] = []
    if isinstance(data, dict):
        for k in ("records","domains","subdomains","hosts","items"):
            v = data.get(k)
            if isinstance(v, list):
                for s in v:
                    nh = norm_host(str(s))
                    if nh:
                        out.append(nh)
        for k in ("result","data"):
            v = data.get(k)
            if isinstance(v, dict):
                for kk in ("records","domains","subdomains","hosts","items"):
                    vv = v.get(kk)
                    if isinstance(vv, list):
                        for s in vv:
                            nh = norm_host(str(s))
                            if nh:
                                out.append(nh)
    out = uniq(out)
    if out:
        log.debug(f"[SecurityTrails] {ip} -> {len(out)} hosts")
    return out

# ---------------- Censys hosts API ----------------

def _collect_hostnames_from_json(obj: Any) -> Set[str]:
    out: Set[str] = set()
    def visit(x: Any):
        if isinstance(x, str):
            nh = norm_host(x)
            if nh:
                out.add(nh)
        elif isinstance(x, dict):
            for v in x.values():
                visit(v)
        elif isinstance(x, (list, tuple)):
            for v in x:
                visit(v)
    visit(obj)
    return out

def censys_domains(ip: str, timeout: float, key: Optional[str]=None, api_id: Optional[str]=None, api_secret: Optional[str]=None) -> List[str]:
    headers = {"User-Agent":"recon/1.0"}
    import base64
    if key:
        headers["Authorization"] = f"Bearer {key}"
    elif api_id and api_secret:
        token = base64.b64encode(f"{api_id}:{api_secret}".encode()).decode()
        headers["Authorization"] = f"Basic {token}"
    else:
        return []
    url = f"https://search.censys.io/api/v2/hosts/{ip}"
    data = _http_json(url, headers=headers, timeout=timeout)
    if not data:
        return []
    hosts = _collect_hostnames_from_json(data)
    out = sorted(hosts)
    if out:
        log.debug(f"[Censys] {ip} -> {len(out)} hosts")
    return out

# ---------------- IPinfo ----------------

def ipinfo_domains(ip: str, token: Optional[str], timeout: float) -> List[str]:
    if not token:
        return []
    headers = {"User-Agent":"recon/1.0"}
    data = _http_json(f"https://ipinfo.io/{ip}/json?token={token}", headers=headers, timeout=timeout)
    out: List[str] = []
    if isinstance(data, dict):
        h = data.get("hostname")
        if isinstance(h, str):
            nh = norm_host(h)
            if nh:
                out.append(nh)
        for k in ("domains","reverse","hosts","items"):
            v = data.get(k)
            if isinstance(v, list):
                for s in v:
                    nh = norm_host(str(s))
                    if nh:
                        out.append(nh)
    out = uniq(out)
    if out:
        log.debug(f"[IPinfo] {ip} -> {len(out)} hosts")
    return out

# ---------------- Domain enumeration (optional) ----------------

def _run_cmd(cmd: List[str], timeout: float, label: str) -> Tuple[int, str, str]:
    log.debug(f"[{label}] cmd: {' '.join(cmd)}")
    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        so = cp.stdout.splitlines()
        se = cp.stderr.strip()
        log.debug(f"[{label}] rc={cp.returncode} stdout_lines={len(so)} stderr_bytes={len(cp.stderr)}")
        if se:
            log.debug(f"[{label}] stderr preview: {se[:400]}")
        return cp.returncode, cp.stdout, cp.stderr
    except subprocess.TimeoutExpired:
        log.warning(f"[{label}] TIMEOUT after {timeout}s")
        return 124, "", ""
    except Exception as e:
        log.error(f"[{label}] exec error: {e}")
        return 1, "", str(e)

def enum_subfinder(domain: str, exe_path: Optional[str], wrapper_timeout: float) -> List[str]:
    exe = exe_path or which("subfinder")
    if not exe:
        log.debug("[subfinder] not found; skipping")
        return []
    cmd = [exe, "-silent", "-all", "-recursive", "-d", domain]
    rc, out, _ = _run_cmd(cmd, wrapper_timeout, f"subfinder[{domain}]")
    if rc not in (0,):  # still use output if any
        log.debug(f"[subfinder[{domain}]] non-zero rc={rc}")
    return [ln.strip() for ln in out.splitlines() if ln.strip()]

def enum_assetfinder(domain: str, exe_path: Optional[str], wrapper_timeout: float) -> List[str]:
    exe = exe_path or which("assetfinder")
    if not exe:
        log.debug("[assetfinder] not found; skipping")
        return []
    cmd = [exe, "--subs-only", domain]
    rc, out, _ = _run_cmd(cmd, wrapper_timeout, f"assetfinder[{domain}]")
    if rc not in (0,):
        log.debug(f"[assetfinder[{domain}]] non-zero rc={rc}")
    return [ln.strip() for ln in out.splitlines() if ln.strip()]

def enum_amass(domain: str, exe_path: Optional[str], wrapper_timeout: float) -> List[str]:
    exe = exe_path or which("amass")
    if not exe:
        log.debug("[amass] not found; skipping")
        return []
    cmd = [exe, "enum", "-passive", "-d", domain, "-nocolor"]
    rc, out, _ = _run_cmd(cmd, wrapper_timeout, f"amass[{domain}]")
    if rc not in (0,):
        log.debug(f"[amass[{domain}]] non-zero rc={rc}")
    return [ln.strip() for ln in out.splitlines() if ln.strip()]

# ---------------- expansion per token ----------------

def expand_token(
    token: str,
    ptr_resolver: PTRResolver,
    use_shodan: bool,
    shodan_key: Optional[str],
    st_key: Optional[str],
    use_st: bool,
    censys_key: Optional[str],
    censys_id: Optional[str],
    censys_secret: Optional[str],
    use_censys: bool,
    ipinfo_key: Optional[str],
    use_ipinfo: bool,
    timeout: float,
    # new: domain enum
    enum_domains: bool,
    enum_tools: List[str],
    enum_time: float,
    subfinder_path: Optional[str],
    assetfinder_path: Optional[str],
    amass_path: Optional[str],
) -> Tuple[str, List[Tuple[str,str]]]:
    """
    Returns (original_token, list of (hostname, source))
    source in {"ptr","shodan","securitytrails","censys","ipinfo","pass","enum:subfinder","enum:assetfinder","enum:amass"}.
    """
    t_start = time.time()
    rows: List[Tuple[str,str]] = []
    if is_ip(token):
        log.debug(f"[Token] {token}: start expansion (IP)")
        # PTR
        t_ptr = time.time()
        ptrs = ptr_resolver.ptr(token)
        log.debug(f"[Token] {token}: PTR done in {time.time()-t_ptr:.3f}s -> {len(ptrs)} names")
        for h in ptrs:
            rows.append((h, "ptr"))
        # Shodan
        if use_shodan and shodan_key:
            t_sh = time.time()
            sh = shodan_reverse(token, shodan_key, timeout)
            log.debug(f"[Token] {token}: Shodan done in {time.time()-t_sh:.3f}s -> {len(sh)} names")
            for h in sh:
                rows.append((h, "shodan"))
        # SecurityTrails
        if use_st and st_key:
            t_st = time.time()
            st = securitytrails_domains(token, st_key, timeout)
            log.debug(f"[Token] {token}: SecurityTrails done in {time.time()-t_st:.3f}s -> {len(st)} names")
            for h in st:
                rows.append((h, "securitytrails"))
        # Censys
        if use_censys and (censys_key or (censys_id and censys_secret)):
            t_ce = time.time()
            ce = censys_domains(token, timeout, key=censys_key, api_id=censys_id, api_secret=censys_secret)
            log.debug(f"[Token] {token}: Censys done in {time.time()-t_ce:.3f}s -> {len(ce)} names")
            for h in ce:
                rows.append((h, "censys"))
        # IPinfo
        if use_ipinfo and ipinfo_key:
            t_ip = time.time()
            ii = ipinfo_domains(token, ipinfo_key, timeout)
            log.debug(f"[Token] {token}: IPinfo done in {time.time()-t_ip:.3f}s -> {len(ii)} names")
            for h in ii:
                rows.append((h, "ipinfo"))
        log.debug(f"[Token] {token}: expansion finished in {time.time()-t_start:.3f}s (rows {len(rows)})")
    else:
        nh = norm_host(token)
        if nh:
            log.debug(f"[Token] {token}: non-IP input")
            # pass-through always
            rows.append((nh, "pass"))
            # optional enumeration
            if enum_domains:
                enum_total = 0
                if "subfinder" in enum_tools:
                    t0 = time.time()
                    subs = [s for s in enum_subfinder(nh, subfinder_path, enum_time) if norm_host(s)]
                    enum_total += len(subs)
                    for s in subs: rows.append((to_ascii_idna(s), "enum:subfinder"))
                    log.debug(f"[Token] {token}: subfinder -> {len(subs)} subs in {time.time()-t0:.2f}s")
                if "assetfinder" in enum_tools:
                    t0 = time.time()
                    subs = [s for s in enum_assetfinder(nh, assetfinder_path, enum_time) if norm_host(s)]
                    enum_total += len(subs)
                    for s in subs: rows.append((to_ascii_idna(s), "enum:assetfinder"))
                    log.debug(f"[Token] {token}: assetfinder -> {len(subs)} subs in {time.time()-t0:.2f}s")
                if "amass" in enum_tools:
                    t0 = time.time()
                    subs = [s for s in enum_amass(nh, amass_path, enum_time) if norm_host(s)]
                    enum_total += len(subs)
                    for s in subs: rows.append((to_ascii_idna(s), "enum:amass"))
                    log.debug(f"[Token] {token}: amass -> {len(subs)} subs in {time.time()-t0:.2f}s")
                if enum_total == 0:
                    log.debug(f"[Token] {token}: enumeration produced no results (or tools unavailable)")
        else:
            log.debug(f"[Token] {token}: not IP and not a valid hostname -> ignored")

    # Deduplicate preferring "stronger" sources if same hostname appears
    rank = {
        "ptr":0,"securitytrails":1,"censys":2,"shodan":3,"ipinfo":4,
        "enum:subfinder":6,"enum:assetfinder":7,"enum:amass":8,
        "pass":9
    }
    best: Dict[str,str] = {}
    for h, src in rows:
        if (h not in best) or (rank.get(src, 99) < rank.get(best[h], 99)):
            best[h] = src
    out = sorted(best.items(), key=lambda kv: (kv[1], kv[0]))
    return token, out

# ---------------- main ----------------

def main():
    ap = argparse.ArgumentParser(description="Expand IP seeds to hostnames (PTR + Shodan + SecurityTrails + Censys + IPinfo) and optionally enumerate domains.")
    ap.add_argument("--in", dest="infile", required=True, help="Input seeds file (domains/hostnames and/or IPs)")
    ap.add_argument("--out", dest="outfile", required=True, help="Output file (hostnames/domains only)")
    ap.add_argument("--emit-map", dest="emit_map", default="", help="Optional CSV mapping (input,hostname,source)")
    ap.add_argument("--workers", type=int, default=32, help="Parallel workers")
    ap.add_argument("--timeout", type=float, default=2.5, help="Per-request timeout seconds")
    ap.add_argument("--resolvers", default="", help="Comma-separated DNS resolvers for PTR (e.g. 1.1.1.1,8.8.8.8)")
    ap.add_argument("--shodan", choices=["yes","no","auto"], default="auto",
                    help="Use Shodan reverse (needs SHODAN_API_KEY). 'auto' enables if env key present.")
    ap.add_argument("--securitytrails", choices=["yes","no","auto"], default="auto",
                    help="Use SecurityTrails reverse IP (needs SECURITYTRAILS_KEY).")
    ap.add_argument("--censys", choices=["yes","no","auto"], default="auto",
                    help="Use Censys hosts API (CENSYS_API_KEY or CENSYS_API_ID+SECRET).")
    ap.add_argument("--ipinfo", choices=["yes","no","auto"], default="auto",
                    help="Use IPinfo hostname (needs IPINFO_API_KEY).")

    # NEW: domain enumeration options
    ap.add_argument("--enum-domains", choices=["yes","no"], default="no",
                    help="If yes, run passive enumeration for non-IP tokens.")
    ap.add_argument("--enum-tools", default="subfinder",
                    help="Comma-separated tools to use for domain enum: subfinder,assetfinder,amass (default: subfinder)")
    ap.add_argument("--enum-wrapper-timeout", type=float, default=1800.0,
                    help="Watchdog timeout (seconds) for each enum tool invocation.")
    ap.add_argument("--enum-workers", type=int, default=8,
                    help="Reserved for future per-domain fanout; currently not used (single-domain per call).")
    ap.add_argument("--subfinder-path", default="", help="Path to subfinder (auto-detect if empty)")
    ap.add_argument("--assetfinder-path", default="", help="Path to assetfinder (auto-detect if empty)")
    ap.add_argument("--amass-path", default="", help="Path to amass (auto-detect if empty)")

    # FCrDNS + logging options
    ap.add_argument("--verify-fcrdns", choices=["yes","no"], default="no",
                    help="If yes, only keep PTR-derived hostnames whose current A/AAAA includes the originating IP.")
    ap.add_argument("--log-level", default="INFO", choices=["DEBUG","INFO","WARNING","ERROR"],
                    help="Console log level (default INFO).")
    ap.add_argument("--log-every", type=int, default=25,
                    help="Emit a progress heartbeat every N tokens processed (default 25).")
    ap.add_argument("--stats-json", default="",
                    help="Optional path to write run statistics as JSON.")

    args = ap.parse_args()
    _setup_logging(args.log_level)

    seeds_path = Path(args.infile).expanduser().resolve()
    out_path   = Path(args.outfile).expanduser().resolve()
    map_path   = Path(args.emit_map).expanduser().resolve() if args.emit_map else None

    seeds = read_lines(seeds_path)
    if not seeds:
        print(f"ERROR: no seeds in {seeds_path}", file=sys.stderr)
        sys.exit(2)

    # seed breakdown for clarity
    num_ips = sum(1 for s in seeds if is_ip(s))
    num_hosts = len(seeds) - num_ips
    log.info(f"Seed breakdown: IPs={num_ips}  Hostnames={num_hosts}")

    resolvers = [x.strip() for x in args.resolvers.split(",") if x.strip()] if args.resolvers else None
    ptr = PTRResolver(resolvers=resolvers, timeout=args.timeout)

    # Keys / toggles
    shodan_key = (os.environ.get("SHODAN_API_KEY") or "").strip() or None
    st_key = (os.environ.get("SECURITYTRAILS_KEY") or "").strip() or None
    censys_key = (os.environ.get("CENSYS_API_KEY") or "").strip() or None
    censys_id = (os.environ.get("CENSYS_API_ID") or "").strip() or None
    censys_secret = (os.environ.get("CENSYS_API_SECRET") or "").strip() or None
    ipinfo_key = (os.environ.get("IPINFO_API_KEY") or "").strip() or None

    use_shodan  = args.shodan == "yes" or (args.shodan == "auto" and shodan_key is not None)
    use_st      = args.securitytrails == "yes" or (args.securitytrails == "auto" and st_key is not None)
    use_censys  = args.censys == "yes" or (args.censys == "auto" and (censys_key or (censys_id and censys_secret)))
    use_ipinfo  = args.ipinfo == "yes" or (args.ipinfo == "auto" and ipinfo_key is not None)

    # enum tool selection
    enum_domains = (args.enum_domains == "yes")
    enum_tools = [t.strip().lower() for t in args.enum_tools.split(",") if t.strip()]
    for t in list(enum_tools):
        if t not in {"subfinder","assetfinder","amass"}:
            log.warning(f"[enum] unknown tool '{t}' ignored")
            enum_tools.remove(t)

    log.info("=== Run Configuration ===")
    log.info(f"Input: {seeds_path}")
    log.info(f"Output: {out_path}")
    if map_path: log.info(f"Emit map: {map_path}")
    log.info(f"Workers: {args.workers}  Timeout: {args.timeout}s  Verify-FCrDNS: {args.verify_fcrdns}")
    log.info(f"Resolvers: {resolvers if resolvers else '(system default)'}")
    log.info(f"APIs: Shodan={use_shodan} SecurityTrails={use_st} Censys={use_censys} IPinfo={use_ipinfo}")
    log.info(f"API keys present: SHODAN={'yes' if shodan_key else 'no'}, SECURITYTRAILS={'yes' if st_key else 'no'}, "
             f"CENSYS={'yes' if (censys_key or (censys_id and censys_secret)) else 'no'}, IPINFO={'yes' if ipinfo_key else 'no'}")
    log.info(f"PTR engine: {'dnspython' if ptr.has_dnspython else 'socket.gethostbyaddr'}")
    log.info(f"Domain enumeration: enabled={enum_domains} tools={enum_tools} timeout={args.enum_wrapper_timeout}s")
    log.info(f"Log-level: {args.log_level}  Progress heartbeat: every {args.log_every} tokens")
    log.info("=========================")

    # fan-out
    t0 = time.time()
    results: List[Tuple[str,List[Tuple[str,str]]]] = []

    # per-source counters for detailed summary (does not affect logic)
    src_counts: Dict[str, int] = {
        "ptr":0,"shodan":0,"securitytrails":0,"censys":0,"ipinfo":0,"pass":0,
        "enum:subfinder":0,"enum:assetfinder":0,"enum:amass":0
    }

    def task(tok: str):
        return expand_token(
            tok, ptr,
            use_shodan, shodan_key,
            st_key, use_st,
            censys_key, censys_id, censys_secret, use_censys,
            ipinfo_key, use_ipinfo,
            args.timeout,
            enum_domains, enum_tools, args.enum_wrapper_timeout,
            args.subfinder_path or None, args.assetfinder_path or None, args.amass_path or None
        )

    processed = 0
    with cf.ThreadPoolExecutor(max_workers=max(args.workers,1)) as ex:
        futs = [ex.submit(task, tok) for tok in seeds]
        for fu in cf.as_completed(futs):
            try:
                item = fu.result()
            except Exception as e:
                # defensive: log and continue
                log.error(f"[Worker] exception: {e}")
                continue
            results.append(item)
            processed += 1
            if args.log_every > 0 and (processed % args.log_every == 0):
                log.info(f"[Progress] {processed}/{len(seeds)} tokens processed")

    # aggregate
    hosts: Set[str] = set()
    map_rows = ["input,hostname,source"] if map_path else None
    for src, pairs in results:
        for h, origin in pairs:
            hosts.add(h)
            if origin in src_counts:
                src_counts[origin] += 1
            if map_rows is not None:
                # (FCrDNS filtering will be applied only to PTR-derived below)
                pass
    hostnames_before_verify = len(hosts)

    # Optional FCrDNS verification: only for PTR-derived hostnames from IP-origin tokens
    if args.verify_fcrdns == "yes":
        # Build origin -> hostnames map limited to PTR
        by_origin: Dict[str, Set[str]] = {}
        for src, pairs in results:
            if is_ip(src):
                for h, origin in pairs:
                    if origin == "ptr":
                        by_origin.setdefault(src, set()).add(h)

        keep_ptr: Set[str] = set()
        fcrdns_checked = 0
        fcrdns_kept = 0
        t_fc = time.time()
        for ip_src in sorted(by_origin.keys()):
            for h in sorted(by_origin[ip_src]):
                fcrdns_checked += 1
                addrs = resolve_addrs(h, resolvers, args.timeout)
                if ip_src in addrs:
                    keep_ptr.add(h)
                    fcrdns_kept += 1
                    log.debug(f"[FCrDNS] KEEP  {h} -> contains {ip_src}")
                else:
                    log.debug(f"[FCrDNS] DROP  {h} -> addrs={sorted(addrs)} (no {ip_src})")
        log.info(f"[FCrDNS] Checked {fcrdns_checked} PTR-host pairs in {time.time()-t_fc:.2f}s; kept {fcrdns_kept}")

        # Apply filter ONLY to PTR-derived hosts; API/pass-through/enumeration stay as-is
        all_ptr_hosts = set().union(*by_origin.values()) if by_origin else set()
        hosts = {h for h in hosts if h not in all_ptr_hosts} | keep_ptr

    # regenerate map rows respecting FCrDNS filter (if any)
    if map_rows is not None:
        for src, pairs in results:
            for h, origin in pairs:
                if args.verify_fcrdns == "yes" and origin == "ptr" and h not in hosts:
                    continue
                map_rows.append(f"{src},{h},{origin}")

    if not hosts:
        print("ERROR: no hostnames after expansion (check DNS / API keys / verify-fcrdns / enum tools).", file=sys.stderr)
        sys.exit(2)

    out = sorted(hosts)
    write_lines(out_path, out)
    if map_rows is not None:
        map_path.parent.mkdir(parents=True, exist_ok=True)
        map_path.write_text("\n".join(map_rows) + "\n", encoding="utf-8")

    elapsed = time.time() - t0
    log.info("=== Summary ===")
    log.info(f"Total seeds: {len(seeds)}  Output hosts: {len(out)}  (before_verify={hostnames_before_verify})")
    if args.verify_fcrdns == "yes":
        log.info("FCrDNS filtering applied to PTR-derived hosts only.")
    # Detailed per-source counts (diagnostic only; does not change logic/output)
    log.info("Per-source rows emitted (pre-dedupe within-token): " +
             ", ".join([f"{k}={src_counts.get(k,0)}" for k in ("ptr","shodan","securitytrails","censys","ipinfo","enum:subfinder","enum:assetfinder","enum:amass","pass")]))
    log.info(f"Duration: {elapsed:.2f}s")
    print(f"Wrote {len(out)} hostnames to {out_path} in {elapsed:.2f}s")
    if map_rows is not None:
        print(f"Wrote mapping CSV to {map_path}")

    # Optional stats json
    if args.stats_json:
        stats = {
            "seeds": len(seeds),
            "hosts_before_verify": hostnames_before_verify,
            "hosts_after_verify": len(out),
            "verify_fcrdns": args.verify_fcrdns,
            "elapsed_seconds": round(elapsed, 3),
            "apis": {"shodan": use_shodan, "securitytrails": use_st, "censys": use_censys, "ipinfo": use_ipinfo},
            "source_rows": src_counts,
            "ptr_engine": "dnspython" if ptr.has_dnspython else "socket",
            "enum": {"enabled": enum_domains, "tools": enum_tools, "timeout": args.enum_wrapper_timeout}
        }
        try:
            Path(args.stats_json).parent.mkdir(parents=True, exist_ok=True)
            Path(args.stats_json).write_text(json.dumps(stats, indent=2) + "\n", encoding="utf-8")
            log.info(f"Wrote stats JSON -> {args.stats_json}")
        except Exception as e:
            log.error(f"Failed writing stats JSON: {e}")

if __name__ == "__main__":
    main()

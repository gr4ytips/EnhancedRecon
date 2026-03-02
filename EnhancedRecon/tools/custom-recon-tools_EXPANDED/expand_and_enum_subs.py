#!/usr/bin/env python3 
"""
Expand seeds (domains/IPs) -> hostnames, passively enumerate subdomains,
OPTIONALLY resolve with dnsx and filter wildcard-only results.

Update (robust dnsx handling):
- Prefer dnsx **file mode** (-l <tmp>) over stdin.
- Try **-json** first (most portable to parse A/AAAA), then **-resp**, then plain text.
- Parse json lines: {"host":"...","a":[...],"aaaa":[...]}
- Still accepts --resolvers and forwards to dnsx/amass.
"""

from __future__ import annotations
import argparse, base64, concurrent.futures as cf, ipaddress, json, os, re, socket, subprocess, sys, tempfile, time, random, string
from pathlib import Path
from typing import Iterable, List, Optional, Set, Tuple, Dict, Any

# ---------------- basic utils ----------------

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
    s = "\n".join(lines)
    if s and not s.endswith("\n"):
        s += "\n"
    p.write_text(s, encoding="utf-8")


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
    h = to_ascii_idna(h)
    if not h:
        return None
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
            pass

    def ptr(self, ip: str) -> List[str]:
        names: List[str] = []
        if self.has_dnspython:
            try:
                rev = self.dns.reversename.from_address(ip)
                ans = self.resolver.resolve(rev, "PTR", lifetime=self.timeout)
                for r in ans:
                    name = str(getattr(r, 'target', r)).rstrip(".")
                    if name:
                        names.append(name)
            except Exception:
                pass
        else:
            try:
                socket.setdefaulttimeout(self.timeout)
                name, aliases, _ = socket.gethostbyaddr(ip)
                cand = [name] + list(aliases)
                for c in cand:
                    c = c.rstrip(".")
                    if c:
                        names.append(c)
            except Exception:
                pass
        out = []
        seen = set()
        for n in names:
            nh = norm_host(n)
            if nh and nh not in seen:
                seen.add(nh)
                out.append(nh)
        return out


# ---------------- Lightweight HTTP JSON ----------------

def _http_json(url: str, headers: Dict[str,str] | None, timeout: float) -> Any:
    import urllib.request, urllib.error
    req = urllib.request.Request(url, headers=headers or {"User-Agent": "recon/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
            return json.loads(data.decode("utf-8", "ignore"))
    except Exception:
        return None


# ---------------- Forward resolve (for FCrDNS) ----------------

def _resolve_addrs(host: str, resolvers: Optional[List[str]], timeout: float) -> Set[str]:
    addrs: Set[str] = set()
    try:
        import dns.resolver as _r  # type: ignore
        r = _r.Resolver(configure=True)
        if resolvers:
            r.nameservers = resolvers
        r.timeout = timeout
        r.lifetime = timeout
        for rrtype in ("A", "AAAA"):
            try:
                ans = r.resolve(host, rrtype, lifetime=timeout)
                for rdata in ans:
                    ip = getattr(rdata, "address", None)
                    if ip:
                        addrs.add(str(ipaddress.ip_address(ip)))
            except Exception:
                pass
    except Exception:
        pass
    try:
        for fam in (socket.AF_INET, socket.AF_INET6):
            try:
                infos = socket.getaddrinfo(host, None, fam, 0, 0, socket.AI_ADDRCONFIG)
                for _f, _t, _p, _c, sa in infos:
                    if sa and sa[0]:
                        addrs.add(str(ipaddress.ip_address(sa[0])))
            except Exception:
                pass
    except Exception:
        pass
    return addrs


# ---------------- External enrichers for IP -> hostnames ----------------

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
    return out


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
    return uniq(out)


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
    return sorted(hosts)


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
    return uniq(out)


# ---------------- Stage A: expand token ----------------

def expand_token(
    token: str,
    ptr_resolver: PTRResolver,
    use_shodan: bool, shodan_key: Optional[str],
    use_st: bool, st_key: Optional[str],
    use_censys: bool, censys_key: Optional[str], censys_id: Optional[str], censys_secret: Optional[str],
    use_ipinfo: bool, ipinfo_key: Optional[str],
    timeout: float
) -> Tuple[str, List[Tuple[str,str]]]:
    rows: List[Tuple[str,str]] = []
    if is_ip(token):
        for h in ptr_resolver.ptr(token):
            rows.append((h, "ptr"))
        if use_shodan and shodan_key:
            for h in shodan_reverse(token, shodan_key, timeout):
                rows.append((h, "shodan"))
        if use_st and st_key:
            for h in securitytrails_domains(token, st_key, timeout):
                rows.append((h, "securitytrails"))
        if use_censys and (censys_key or (censys_id and censys_secret)):
            for h in censys_domains(token, timeout, key=censys_key, api_id=censys_id, api_secret=censys_secret):
                rows.append((h, "censys"))
        if use_ipinfo and ipinfo_key:
            for h in ipinfo_domains(token, ipinfo_key, timeout):
                rows.append((h, "ipinfo"))
    else:
        nh = norm_host(token)
        if nh:
            rows.append((nh, "pass"))

    rank = {"ptr":0,"securitytrails":1,"censys":2,"shodan":3,"ipinfo":4,"pass":5}
    best: Dict[str,str] = {}
    for h, src in rows:
        if (h not in best) or (rank[src] < rank[best[h]]):
            best[h] = src
    return token, sorted(best.items(), key=lambda kv: (kv[1], kv[0]))


# ---------------- helpers ----------------

def _run_cmd(cmd: List[str], timeout: float, debug: bool, label: str, stdin_text: str | None = None) -> Tuple[int, str, str]:
    if debug:
        print(f"[{label}] cmd: {' '.join(cmd)}", file=sys.stderr)
    try:
        cp = subprocess.run(cmd, input=stdin_text, text=True, capture_output=True, timeout=timeout)
        if debug:
            so = cp.stdout.splitlines()
            se = cp.stderr.strip()
            print(f"[{label}] rc={cp.returncode} stdout_lines={len(so)} stderr_bytes={len(cp.stderr)}", file=sys.stderr)
            if so:
                preview = "\n".join(so[:min(5,len(so))])
                print(f"[{label}] stdout preview:\n{preview}", file=sys.stderr)
            if se:
                print(f"[{label}] stderr preview:\n{se[:400]}", file=sys.stderr)
        return cp.returncode, cp.stdout, cp.stderr
    except subprocess.TimeoutExpired:
        if debug:
            print(f"[{label}] TIMEOUT after {timeout}s", file=sys.stderr)
        return 124, "", ""
    except Exception as e:
        if debug:
            print(f"[{label}] exec error: {e}", file=sys.stderr)
        return 1, "", str(e)


# ---------------- Stage B: passive subdomain enumeration ----------------

SUBFINDER_TIMEOUT = 1800.0  # 30 minutes watchdog
AMASS_TIMEOUT     = 1800.0  # 30 minutes watchdog


def enum_subfinder(domains: List[str], debug: bool) -> List[str]:
    exe = which("subfinder")
    if not exe or not domains:
        if debug and not exe:
            print("[subfinder] not found", file=sys.stderr)
        return []
    with tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False) as tf:
        for d in domains:
            tf.write(d + "\n")
        tf.flush()
        tmp_path = tf.name
    if debug:
        print(f"[subfinder] wrote {len(domains)} domains to {tmp_path}", file=sys.stderr)

    cmd = [exe, "-dL", tmp_path, "-all", "-recursive"]
    rc, out, _ = _run_cmd(cmd, timeout=SUBFINDER_TIMEOUT, debug=debug, label="subfinder")

    try:
        Path(tmp_path).unlink(missing_ok=True)
    except Exception:
        pass

    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return lines


def enum_assetfinder(domains: List[str], timeout: float, workers: int, debug: bool) -> List[str]:
    exe = which("assetfinder")
    if not exe or not domains:
        if debug and not exe:
            print("[assetfinder] not found", file=sys.stderr)
        return []
    out: List[str] = []

    def task(d: str) -> List[str]:
        rc, so, _ = _run_cmd([exe, "--subs-only", d], timeout=timeout, debug=debug, label=f"assetfinder[{d}]")
        if so:
            return [ln.strip() for ln in so.splitlines() if ln.strip()]
        return []

    with cf.ThreadPoolExecutor(max_workers=max(workers, 4)) as ex:
        for res in ex.map(task, domains):
            out.extend(res)
    return out


def enum_amass(domains: List[str], resolvers: Optional[List[str]], debug: bool) -> List[str]:
    exe = which("amass")
    if not exe or not domains:
        if debug and not exe:
            print("[amass] not found", file=sys.stderr)
        return []
    with tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False) as tf:
        for d in domains:
            tf.write(d + "\n")
        tf.flush()
        tmp_path = tf.name
    if debug:
        print(f"[amass] wrote {len(domains)} domains to {tmp_path}", file=sys.stderr)

    cmd = [exe, "enum", "-passive", "-df", tmp_path, "-nocolor"]
    if resolvers:
        cmd += ["-r", ",".join(resolvers)]
    rc, out, _ = _run_cmd(cmd, timeout=AMASS_TIMEOUT, debug=debug, label="amass")

    try:
        Path(tmp_path).unlink(missing_ok=True)
    except Exception:
        pass

    lines = [ln.strip() for ln in out.splitlines() if ln.strip()]
    return lines


# ---------------- Stage C: dnsx resolve + wildcard filter ----------------


def random_label(n: int = 12) -> str:
    alphabet = string.ascii_lowercase + string.digits
    return "".join(random.choice(alphabet) for _ in range(n))


def _parse_dnsx_plain(lines: List[str]) -> Dict[str, Set[str]]:
    mapping: Dict[str, Set[str]] = {}
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        parts = s.split()
        host = to_ascii_idna(parts[0].rstrip(".")) if parts else ""
        if not norm_host(host):
            continue
        ips = mapping.setdefault(host, set())
        for tok in parts[1:]:
            tok = tok.strip("[](),")
            if tok and (is_ip(tok) or re.match(r"^[0-9a-f:]+$", tok, re.I)):
                ips.add(tok)
    return mapping


def _parse_dnsx_json(out_text: str) -> Dict[str, Set[str]]:
    mapping: Dict[str, Set[str]] = {}
    for line in out_text.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        host = to_ascii_idna(str(obj.get("host", "")).rstrip("."))
        if not norm_host(host):
            continue
        ips = mapping.setdefault(host, set())
        for key in ("a", "aaaa"):
            vals = obj.get(key, [])
            if isinstance(vals, list):
                for v in vals:
                    try:
                        ip = str(ipaddress.ip_address(str(v)))
                        ips.add(ip)
                    except Exception:
                        pass
    return mapping


def run_dnsx(hosts: List[str], dnsx_path: Optional[str], timeout_s: float, rate: float, retries: int,
             resolvers: Optional[List[str]] = None, debug: bool = False) -> Dict[str, Set[str]]:
    exe = dnsx_path or which("dnsx")
    if not exe or not hosts:
        if debug:
            why = "no dnsx" if not exe else "no hosts"
            print(f"[dnsx] skip: {why}", file=sys.stderr)
        return {}

    int_rate = int(rate)

    # Always prefer file mode
    with tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False) as tf:
        for h in hosts:
            tf.write(h + "\n")
        tf.flush()
        list_path = tf.name

    if debug:
        print(f"[dnsx] list file: {list_path} ({len(hosts)} hosts)", file=sys.stderr)
        if resolvers:
            print(f"[dnsx] resolvers: {','.join(resolvers)}", file=sys.stderr)

    def call(args_add: List[str], label: str) -> Tuple[int, str, str]:
        cmd = [exe, "-l", list_path, "-silent", "-a", "-aaaa", "-retry", str(max(0, retries)),
               "-rl", str(int_rate), "-t", str(int(max(1, timeout_s)))] + args_add
        if resolvers:
            cmd += ["-r", ",".join(resolvers)]
        return _run_cmd(cmd, timeout=max(120, int(timeout_s) * 5), debug=debug, label=f"dnsx/{label}")

    # 1) JSON mode
    rc, out, err = call(["-json"], "json")
    try:
        parsed = _parse_dnsx_json(out)
    except Exception:
        parsed = {}

    # 2) -resp fallback
    if not parsed:
        rc2, out2, err2 = call(["-resp"], "resp")
        parsed = _parse_dnsx_plain(out2.splitlines())

    # 3) plain fallback
    if not parsed:
        rc3, out3, err3 = call([], "plain")
        parsed = _parse_dnsx_plain(out3.splitlines())

    try:
        Path(list_path).unlink(missing_ok=True)
    except Exception:
        pass

    if debug:
        print(f"[dnsx] parsed hosts: {len(parsed)}", file=sys.stderr)
        shown = 0
        for h, ips in parsed.items():
            print(f"[dnsx]   {h} -> {', '.join(sorted(ips)) if ips else '(no IPs)'}", file=sys.stderr)
            shown += 1
            if shown >= 5:
                if len(parsed) > shown:
                    print(f"[dnsx]   ... (+{len(parsed)-shown} more)", file=sys.stderr)
                break

    return parsed


def wildcard_probe(apexes: List[str], dnsx_path: Optional[str], timeout_s: float, rate: float, retries: int, samples: int, resolvers: Optional[List[str]], debug: bool = False) -> Dict[str, Set[str]]:
    probes: List[str] = []
    owner: Dict[str, List[str]] = {}
    for a in apexes:
        cand = []
        for _ in range(max(1, samples)):
            lab = random_label()
            fq = f"{lab}.{a}"
            cand.append(fq)
            probes.append(fq)
        owner[a] = cand
    res_map = run_dnsx(probes, dnsx_path, timeout_s, rate, retries, resolvers, debug)
    out: Dict[str, Set[str]] = {a: set() for a in apexes}
    for a, cands in owner.items():
        ips: Set[str] = set()
        for fq in cands:
            h = to_ascii_idna(fq)
            ips |= res_map.get(h, set())
        out[a] = ips
    return out


def in_scope(host: str, roots: List[str]) -> bool:
    h = to_ascii_idna(host)
    for r in roots:
        rr = to_ascii_idna(r)
        if h == rr or h.endswith("." + rr):
            return True
    return False


# ---------------- main ----------------

def main():
    ap = argparse.ArgumentParser(description="Expand IPs -> hostnames; passive subdomain enum; optional dnsx + wildcard filter.")
    ap.add_argument("--in", dest="infile", required=True, help="Seeds file (domains/hostnames and/or IPs)")
    ap.add_argument("--out-dir", dest="out_dir", required=True, help="Output directory")
    ap.add_argument("--emit-map", dest="emit_map", default="", help="Optional CSV mapping (input,hostname,source)")
    ap.add_argument("--workers", type=int, default=32, help="Workers for PTR/assetfinder loops")
    ap.add_argument("--timeout", type=float, default=2.5, help="Per-request timeout seconds")
    ap.add_argument("--resolvers", default="", help="Comma-separated DNS resolvers for PTR/dnsx/amass (e.g. 1.1.1.1,8.8.8.8)")
    ap.add_argument("--verify-fcrdns", choices=["yes","no"], default="no", help="Verify PTR hostnames map back to origin IP (A/AAAA)")

    ap.add_argument("--shodan", choices=["yes","no","auto"], default="auto")
    ap.add_argument("--securitytrails", choices=["yes","no","auto"], default="auto")
    ap.add_argument("--censys", choices=["yes","no","auto"], default="auto")
    ap.add_argument("--ipinfo", choices=["yes","no","auto"], default="auto")

    ap.add_argument("--enumerate", choices=["yes","no"], default="yes", help="Run passive subdomain enumeration")
    ap.add_argument("--restrict-suffix", default="", help="Comma-separated apexes to keep (default = all expanded seeds)")
    ap.add_argument("--include-apex", choices=["yes","no"], default="no", help="Include apexes in final subs")

    ap.add_argument("--resolve", choices=["yes","no"], default="yes", help="Run dnsx resolution stage")
    ap.add_argument("--dnsx-path", default="", help="Path to dnsx (default: auto detect)")
    ap.add_argument("--dnsx-rate", type=float, default=200.0, help="dnsx rate limit (rl) — integer on some builds")
    ap.add_argument("--dnsx-retries", type=int, default=2, help="dnsx -retry count")
    ap.add_argument("--dnsx-timeout", type=float, default=4.0, help="dnsx -t seconds")
    ap.add_argument("--wildcard-filter", choices=["yes","no"], default="yes", help="Filter likely wildcard-only hosts")
    ap.add_argument("--wildcard-samples", type=int, default=3, help="Random labels per apex to detect wildcard IPs")
    ap.add_argument("--wildcard-max-ips", type=int, default=2, help="If host IP set ⊆ apex wildcard IPs and size ≤ this, drop it")
    ap.add_argument("--debug", choices=["yes","no"], default="no", help="Verbose command + output previews")
    args = ap.parse_args()

    debug = (args.debug == "yes")

    in_path = Path(args.infile).expanduser().resolve()
    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    seeds_raw = read_lines(in_path)
    if not seeds_raw:
        print(f"ERROR: no seeds in {in_path}", file=sys.stderr)
        sys.exit(2)

    resolvers = [x.strip() for x in args.resolvers.split(",") if x.strip()] if args.resolvers else None
    if debug:
        print(f"[cfg] resolvers: {resolvers if resolvers else '(system default)'}", file=sys.stderr)
    ptr = PTRResolver(resolvers=resolvers, timeout=args.timeout)

    # API keys
    shodan_key = (os.environ.get("SHODAN_API_KEY") or "").strip() or None
    st_key = (os.environ.get("SECURITYTRAILS_KEY") or "").strip() or None
    censys_key = (os.environ.get("CENSYS_API_KEY") or "").strip() or None
    censys_id = (os.environ.get("CENSYS_API_ID") or "").strip() or None
    censys_secret = (os.environ.get("CENSYS_API_SECRET") or "").strip() or None
    ipinfo_key = (os.environ.get("IPINFO_API_KEY") or "").strip() or None

    use_shodan   = args.shodan == "yes"         or (args.shodan == "auto"         and shodan_key)
    use_st       = args.securitytrails == "yes" or (args.securitytrails == "auto" and st_key)
    use_censys   = args.censys == "yes"         or (args.censys == "auto"         and (censys_key or (censys_id and censys_secret)))
    use_ipinfo   = args.ipinfo == "yes"         or (args.ipinfo == "auto"         and ipinfo_key)

    # -------- Stage A: expand to hostnames --------
    t0 = time.time()
    results: List[Tuple[str,List[Tuple[str,str]]]] = []

    def task(tok: str):
        return expand_token(tok, ptr,
            bool(use_shodan), shodan_key,
            bool(use_st), st_key,
            bool(use_censys), censys_key, censys_id, censys_secret,
            bool(use_ipinfo), ipinfo_key,
            args.timeout
        )

    with cf.ThreadPoolExecutor(max_workers=max(args.workers,1)) as ex:
        futs = [ex.submit(task, tok) for tok in seeds_raw]
        for fu in cf.as_completed(futs):
            results.append(fu.result())

    # FCrDNS pruning for PTR-derived names
    fcrdns_mode = (args.verify_fcrdns == "yes")
    allowed_ptr: Dict[str, Set[str]] = {}
    if fcrdns_mode:
        by_origin: Dict[str, Set[str]] = {}
        for src, pairs in results:
            if is_ip(src):
                for h, origin in pairs:
                    if origin == "ptr":
                        by_origin.setdefault(src, set()).add(h)
        for ip_src, hosts in by_origin.items():
            for h in hosts:
                addrs = _resolve_addrs(h, resolvers, args.timeout)
                if ip_src in addrs:
                    allowed_ptr.setdefault(ip_src, set()).add(h)

    host_set: Set[str] = set()
    map_rows = ["input,hostname,source"] if args.emit_map else None
    for src, pairs in results:
        for h, origin in pairs:
            if fcrdns_mode and origin == "ptr" and is_ip(src):
                if h not in allowed_ptr.get(src, set()):
                    continue
            host_set.add(h)
            if map_rows is not None:
                map_rows.append(f"{src},{h},{origin}")

    seeds_expanded = sorted(host_set)
    if not seeds_expanded:
        print("ERROR: no hostnames after Stage A expansion.", file=sys.stderr)
        sys.exit(2)

    seeds_expanded_path = out_dir / "seeds_expanded.txt"
    write_lines(seeds_expanded_path, seeds_expanded)
    if map_rows is not None:
        (out_dir / Path(args.emit_map)).write_text("\n".join(map_rows) + "\n", encoding="utf-8")

    print(f"[A] Expanded to {len(seeds_expanded)} hostnames -> {seeds_expanded_path} ({time.time()-t0:.2f}s)" + (" [FCrDNS]" if fcrdns_mode else ""))

    # -------- Scope roots --------
    if args.restrict_suffix:
        scope_roots = [to_ascii_idna(s) for s in args.restrict_suffix.split(",") if s.strip()]
    else:
        scope_roots = list(seeds_expanded)

    # -------- Stage B: passive enumeration --------
    if args.enumerate == "yes":
        apexes = scope_roots[:]
        t1 = time.time()
        subs_subfinder = [s for s in enum_subfinder(apexes, debug=debug) if norm_host(s)]
        write_lines(out_dir / "subs_subfinder.txt", sorted(set(subs_subfinder)))
        print(f"[B] subfinder: {len(set(subs_subfinder))} subs ({time.time()-t1:.2f}s)")

        t2 = time.time()
        subs_assetfinder = [s for s in enum_assetfinder(apexes, timeout=max(args.timeout, 30.0), workers=args.workers, debug=debug) if norm_host(s)]
        write_lines(out_dir / "subs_assetfinder.txt", sorted(set(subs_assetfinder)))
        print(f"[B] assetfinder: {len(set(subs_assetfinder))} subs ({time.time()-t2:.2f}s)")

        t3 = time.time()
        subs_amass: List[str] = []
        if os.environ.get("RUN_AMASS", "no").lower() in ("1","true","yes","y"):
            subs_amass = [s for s in enum_amass(apexes, resolvers, debug=debug) if norm_host(s)]
            write_lines(out_dir / "subs_amass.txt", sorted(set(subs_amass)))
            print(f"[B] amass: {len(set(subs_amass))} subs ({time.time()-t3:.2f}s)")
        else:
            print("[B] amass: skipped (set RUN_AMASS=yes to enable)")

        combined = set(subs_subfinder) | set(subs_assetfinder) | set(subs_amass)
        combined_norm = {to_ascii_idna(x) for x in combined if norm_host(x)}
        write_lines(out_dir / "subs_combined.txt", sorted(combined_norm))

        scoped = sorted({s for s in combined_norm if in_scope(s, scope_roots)})
        write_lines(out_dir / "subs_scoped.txt", scoped)

        final = sorted(set(seeds_expanded) | set(scoped))
        if args.include_apex.lower() == "yes":
            final = sorted(set(final) | set(apexes))
        write_lines(out_dir / "subs_unique.txt", final)

        print(f"[B] Combined: {len(combined_norm)} | Scoped: {len(scoped)} | Final: {len(final)} -> {out_dir/'subs_unique.txt'}")
    else:
        final = seeds_expanded[:]
        write_lines(out_dir / "subs_unique.txt", final)
        print("[B] Enumeration disabled; using expanded hostnames as final list.")

    # -------- Stage C: dnsx resolve + wildcard filtering --------
    if args.resolve == "yes":
        dnsx_path = args.dnsx_path or which("dnsx")
        if not dnsx_path:
            print("[C] dnsx not found — skipping Stage C.")
            return

        targets = read_lines(out_dir / "subs_unique.txt")
        if not targets:
            print("[C] No targets to resolve; skipping Stage C.")
            return

        print(f"[C] Resolving {len(targets)} hosts with dnsx ...")
        res_map = run_dnsx(targets, dnsx_path, args.dnsx_timeout, args.dnsx_rate, args.dnsx_retries, resolvers, debug)
        rows = ["hostname,ips"]
        for h in sorted(set(targets)):
            ips = sorted(res_map.get(h, set()))
            rows.append(f"{h},{'|'.join(ips)}")
        (out_dir / "dns_resolved.csv").write_text("\n".join(rows) + "\n", encoding="utf-8")

        if args.wildcard_filter == "yes":
            print("[C] Wildcard probing ...")
            wc_map = wildcard_probe(scope_roots, dnsx_path, args.dnsx_timeout, args.dnsx_rate, args.dnsx_retries, args.wildcard_samples, resolvers, debug)
            probe_rows = ["apex,random_label,ips"]
            for a, _ in wc_map.items():
                for _i in range(args.wildcard_samples):
                    lab = random_label()
                    fq = f"{lab}.{a}"
                    ips = sorted(run_dnsx([fq], dnsx_path, args.dnsx_timeout, args.dnsx_rate, args.dnsx_retries, resolvers, debug).get(to_ascii_idna(fq), set()))
                    probe_rows.append(f"{a},{fq},{'|'.join(ips)}")
            (out_dir / "dns_wildcard_probes.csv").write_text("\n".join(probe_rows) + "\n", encoding="utf-8")

            def is_wildcard_like(host: str) -> bool:
                ips = res_map.get(host, set())
                if not ips:
                    return False
                if len(ips) > max(1, args.wildcard_max_ips):
                    return False
                for a in scope_roots:
                    if host == a or host.endswith("." + a):
                        wc_ips = wc_map.get(a, set())
                        if ips and wc_ips and ips.issubset(wc_ips):
                            return True
                return False

            filtered = [h for h in targets if not is_wildcard_like(h)]
        else:
            filtered = targets

        resolved_hosts = sorted([h for h in filtered if res_map.get(h)])
        unresolved_hosts = sorted(set(filtered) - set(resolved_hosts))

        write_lines(out_dir / "subs_nowildcard.txt", filtered)
        write_lines(out_dir / "subs_nowildcard_resolved.txt", resolved_hosts)
        write_lines(out_dir / "subs_unresolved.txt", unresolved_hosts)

        print(f"[C] Filtered: {len(filtered)} | Resolved: {len(resolved_hosts)} | Unresolved: {len(unresolved_hosts)}")
    else:
        print("[C] Resolution stage disabled (--resolve no).")


if __name__ == "__main__":
    main()

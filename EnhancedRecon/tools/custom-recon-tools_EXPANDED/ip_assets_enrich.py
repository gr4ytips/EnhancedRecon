#!/usr/bin/env python3
"""
ip_assets_enrich.py
-------------------
Expand CIDRs & IPs, optionally resolve domains, add PTR + ASN/Org/Country, optional TCP liveness probes,
and export to XLSX/CSV. Designed for clean dedupe, progress logging, and easy analysis.

Requirements:
    pip install ipwhois xlsxwriter
    (dnsx optional: https://github.com/projectdiscovery/dnsx)
"""

from __future__ import annotations
import argparse, csv, json, socket, time, logging, subprocess, shlex, tempfile, re
from pathlib import Path
from typing import Dict, List, Tuple, Iterable, Optional, Set, DefaultDict
import concurrent.futures as cf
import ipaddress
import ssl
from collections import defaultdict

# Optional libs
try:
    from ipwhois import IPWhois
except Exception:
    IPWhois = None

LOG = logging.getLogger("ip_assets_enrich")

# ------------------- helpers -------------------

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def read_lines(p: Path) -> List[str]:
    if not p or not Path(p).exists():
        return []
    return [ln.rstrip("\n") for ln in Path(p).read_text(encoding="utf-8", errors="ignore").splitlines()]

def setup_logging(level: str):
    lvl = getattr(logging, level.upper(), logging.INFO)
    logging.basicConfig(
        level=lvl,
        format="%(asctime)s | %(levelname)-5s | %(message)s",
        datefmt="%H:%M:%S",
    )

def which(cmd: str) -> Optional[str]:
    from shutil import which as _which
    return _which(cmd)

# ------------------- input parsing -------------------

def parse_targets(lines: Iterable[str]) -> Tuple[Set[str], Dict[str, str]]:
    """
    Return (ips, source_map). Expands all CIDRs (IPv4 hosts(); IPv6 entire prefix),
    deduplicates IPs, and records how each IP appeared (input_ip, input_cidr).
    """
    seen_sources: Dict[str, Set[str]] = {}
    for raw in lines:
        if not raw:
            continue
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        try:
            if "/" in s:
                net = ipaddress.ip_network(s, strict=False)
                itr = net.hosts() if net.version == 4 else net
                for ip in itr:
                    ip_s = str(ip)
                    seen_sources.setdefault(ip_s, set()).add("input_cidr")
            else:
                ip_s = str(ipaddress.ip_address(s))
                seen_sources.setdefault(ip_s, set()).add("input_ip")
        except Exception:
            LOG.debug("Skipping invalid target: %r", s)
            continue
    ips = set(seen_sources.keys())
    source_map = {ip: ",".join(sorted(srcs)) for ip, srcs in seen_sources.items()}
    return ips, source_map

def parse_domains(dom_lines: Iterable[str]) -> List[str]:
    """
    Clean & dedupe domains: trim, lowercase, drop leading '*.' and comments.
    """
    out: Set[str] = set()
    for raw in dom_lines:
        if not raw:
            continue
        s = raw.strip()
        if not s or s.startswith("#"):
            continue
        s = s.lower()
        if s.startswith("*."):
            s = s[2:]
        # basic sanity
        if " " in s or "/" in s:
            continue
        out.add(s)
    domains = sorted(out)
    LOG.info("[DOMAINS] %d unique domain(s) after cleanup", len(domains))
    return domains

# ------------------- PTR lookups -------------------

def ptr_lookup_python(ips: List[str], timeout: float = 3.5, workers: int = 64, log_every: int = 250) -> Dict[str, str]:
    t0 = time.time()
    socket.setdefaulttimeout(timeout)
    def _one(ip: str):
        try:
            name, _, _ = socket.gethostbyaddr(ip)
            return ip, name.rstrip(".")
        except Exception:
            return ip, ""
    out: Dict[str,str] = {}
    LOG.info("[PTR] Python gethostbyaddr for %d IPs (timeout=%.1fs, workers=%d)", len(ips), timeout, workers)
    with cf.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        for idx, (ip, host) in enumerate(ex.map(_one, ips), start=1):
            out[ip] = host
            if idx % log_every == 0:
                LOG.debug("[PTR] %d/%d done...", idx, len(ips))
    dt = time.time() - t0
    resolved = sum(1 for v in out.values() if v)
    LOG.info("[PTR] complete in %.2fs; resolved=%d (%.1f%%)", dt, resolved, 100.0*resolved/max(1,len(ips)))
    return out

def _dnsx_call_list(items: List[str],
                    base_args: List[str],
                    dnsx_path: str,
                    resolvers: Optional[List[str]],
                    resolvers_file: Optional[str],
                    dnsx_opts: str,
                    label: str,
                    rate: int,
                    timeout_s: int,
                    retries: int,
                    hard_timeout_sec: Optional[int] = None) -> Tuple[int, str, str]:
    exe = dnsx_path or "dnsx"
    if which(exe) is None:
        return 127, "", f"{exe} not found"
    # write list file
    with tempfile.NamedTemporaryFile("w+", encoding="utf-8", delete=False) as tf:
        for it in items:
            tf.write(it + "\n")
        tf.flush()
        list_path = tf.name
    cmd = [exe, "-l", list_path, *base_args]
    # common tuning flags
    cmd += ["-silent", "-rl", str(max(1, int(rate))), "-t", str(max(1, int(timeout_s))), "-retry", str(max(0, int(retries)))]
    # resolvers: prefer -r list, else -rf file
    if resolvers and len(resolvers) > 0:
        cmd += ["-r", ",".join(resolvers)]
    elif resolvers_file:
        cmd += ["-rf", resolvers_file]
    if dnsx_opts:
        cmd += shlex.split(dnsx_opts)
    LOG.info("[%s] dnsx via: %s", label, " ".join(shlex.quote(c) for c in cmd))

    # Auto-scale hard timeout if not explicitly set: base 90s + work estimate, cap 1h
    if not hard_timeout_sec or hard_timeout_sec <= 0:
        est = 90 + int((len(items) / max(1, rate)) * max(1, retries + 1) * (timeout_s + 2))
        hard_timeout_sec = max(120, min(3600, est))

    try:
        cp = subprocess.run(cmd, capture_output=True, text=True, timeout=hard_timeout_sec)
        return cp.returncode, cp.stdout, cp.stderr
    except subprocess.TimeoutExpired as e:
        out = getattr(e, "output", "") or ""
        err = getattr(e, "stderr", "") or ""
        LOG.error("[%s] dnsx timed out after %ss (items=%d). Consider lowering --dnsx-rate, "
                  "raising --dnsx-timeout or using --dnsx-hard-timeout.", label, hard_timeout_sec, len(items))
        return 124, out, (err or f"timeout after {hard_timeout_sec}s")
    finally:
        try: Path(list_path).unlink(missing_ok=True)
        except Exception: pass

_IP_RE = re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b")

def _looks_host(s: str) -> bool:
    s = s.strip().strip(".")
    if not s: return False
    if "." not in s: return False
    if " " in s: return False
    return True

def _parse_ptr_json_lines(lines: List[str]) -> Dict[str,str]:
    """
    Accepts multiple JSON shapes:
      {"host":"IP","answer":"ptr.name"}
      {"host":"IP","ptr":"ptr.name"} or {"host":"IP","ptr":["ptr.name"]}
      {"host":"IP","answers":["ptr.name", ...]}
    """
    out: Dict[str,str] = {}
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except Exception:
            continue
        ip = str(obj.get("host") or obj.get("ip") or "")
        # gather candidates from string-or-list fields
        cands: List[str] = []
        for key in ("answer", "ptr", "answers"):
            v = obj.get(key)
            if isinstance(v, str):
                cands.append(v)
            elif isinstance(v, list):
                for x in v:
                    if isinstance(x, str):
                        cands.append(x)
        name = ""
        for c in cands:
            cc = c.rstrip(".")
            if _looks_host(cc):
                name = cc
                break
        if ip and name:
            out[ip] = name
    return out

def _parse_ptr_text_lines(lines: List[str]) -> Dict[str,str]:
    """
    Parse -resp or plain text lines, being permissive:
      "1.1.1.1 [PTR] [one.one.one.one]"
      "1.1.1.1 one.one.one.one"
      "8.8.8.8 [PTR] [dns.google]"
    """
    out: Dict[str,str] = {}
    for ln in lines:
        s = ln.strip()
        if not s:
            continue
        ips = _IP_RE.findall(s)
        if not ips:
            continue
        ip = ips[0]
        parts = s.split()
        host = ""
        for tok in reversed(parts):
            tok = tok.strip(",[]()")
            if _looks_host(tok):
                host = tok.rstrip(".")
                break
        if not host:
            continue
        out[ip] = host
    return out

def ptr_lookup_dnsx(ips: List[str],
                    dnsx_path: str,
                    resolvers: Optional[List[str]],
                    resolvers_file: Optional[str],
                    dnsx_rate: int,
                    dnsx_timeout: int,
                    dnsx_retries: int,
                    dnsx_opts: str = "",
                    dnsx_hard_timeout: int = 0) -> Dict[str,str]:
    """
    Try PTR with dnsx in this order:
      1) JSON:  -ptr -json
      2) RESP:  -ptr -resp
      3) PLAIN: -ptr
    Parse each style; if all fail, fall back to Python.
    """
    if which(dnsx_path or "dnsx") is None:
        LOG.warning("[PTR] dnsx not found; falling back to Python")
        return ptr_lookup_python(ips)

    # ---- 1) JSON
    rc, out, err = _dnsx_call_list(
        items=ips,
        base_args=["-ptr", "-json"],
        dnsx_path=dnsx_path,
        resolvers=resolvers,
        resolvers_file=resolvers_file,
        dnsx_opts=dnsx_opts,
        label="PTR/json",
        rate=dnsx_rate,
        timeout_s=dnsx_timeout,
        retries=dnsx_retries,
        hard_timeout_sec=dnsx_hard_timeout
    )
    lines = out.splitlines() if out else []
    parsed = _parse_ptr_json_lines(lines)
    if parsed:
        LOG.info("[PTR] dnsx(JSON) parsed: %d/%d", len(parsed), len(ips))
        return parsed
    LOG.warning("[PTR] dnsx(JSON) yielded no parseable PTR; rc=%s stderr=%s", rc, (err or "")[:160])

    # ---- 2) RESP
    rc2, out2, err2 = _dnsx_call_list(
        items=ips,
        base_args=["-ptr", "-resp"],
        dnsx_path=dnsx_path,
        resolvers=resolvers,
        resolvers_file=resolvers_file,
        dnsx_opts=dnsx_opts,
        label="PTR/resp",
        rate=dnsx_rate,
        timeout_s=dnsx_timeout,
        retries=dnsx_retries,
        hard_timeout_sec=dnsx_hard_timeout
    )
    lines2 = out2.splitlines() if out2 else []
    parsed2 = _parse_ptr_text_lines(lines2)
    if parsed2:
        LOG.info("[PTR] dnsx(RESP) parsed: %d/%d", len(parsed2), len(ips))
        return parsed2
    LOG.warning("[PTR] dnsx(RESP) yielded no parseable PTR; rc=%s stderr=%s", rc2, (err2 or "")[:160])

    # ---- 3) PLAIN
    rc3, out3, err3 = _dnsx_call_list(
        items=ips,
        base_args=["-ptr"],
        dnsx_path=dnsx_path,
        resolvers=resolvers,
        resolvers_file=resolvers_file,
        dnsx_opts=dnsx_opts,
        label="PTR/plain",
        rate=dnsx_rate,
        timeout_s=dnsx_timeout,
        retries=dnsx_retries,
        hard_timeout_sec=dnsx_hard_timeout
    )
    lines3 = out3.splitlines() if out3 else []
    parsed3 = _parse_ptr_text_lines(lines3)
    if parsed3:
        LOG.info("[PTR] dnsx(PLAIN) parsed: %d/%d", len(parsed3), len(ips))
        return parsed3
    LOG.warning("[PTR] dnsx(PLAIN) yielded no parseable PTR; rc=%s stderr=%s", rc3, (err3 or "")[:160])

    # ---- Fallback
    LOG.warning("[PTR] falling back to Python gethostbyaddr()")
    return ptr_lookup_python(ips)

# ------------------- forward DNS (domains -> IPs) -------------------

def resolve_domains_python(domains: List[str], timeout: float = 2.0, workers: int = 128, log_every: int = 500) -> Dict[str, Set[str]]:
    """
    Resolve A/AAAA using socket.getaddrinfo; returns mapping domain -> set(IPs).
    """
    socket.setdefaulttimeout(timeout)
    def _one(domain: str) -> Tuple[str, Set[str]]:
        ips: Set[str] = set()
        try:
            infos = socket.getaddrinfo(domain, None, 0, 0, 0, 0)
            for _fam, *_rest, sa in infos:
                ip = sa[0]
                ips.add(ip)
        except Exception:
            pass
        return domain, ips

    out: Dict[str, Set[str]] = {}
    LOG.info("[DNS] Python resolver for %d domain(s) (timeout=%.1fs, workers=%d)", len(domains), timeout, workers)
    with cf.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        for idx, (dom, ips) in enumerate(ex.map(_one, domains), start=1):
            out[dom] = ips
            if idx % log_every == 0:
                LOG.debug("[DNS] %d/%d domains resolved...", idx, len(domains))
    resolved = sum(1 for s in out.values() if s)
    LOG.info("[DNS] complete; resolved %d/%d domains", resolved, len(domains))
    return out

def resolve_domains_dnsx(domains: List[str],
                         dnsx_path: str,
                         resolvers: Optional[List[str]],
                         resolvers_file: Optional[str],
                         dnsx_rate: int,
                         dnsx_timeout: int,
                         dnsx_retries: int,
                         dnsx_opts: str = "",
                         dnsx_hard_timeout: int = 0) -> Dict[str, Set[str]]:
    """
    Use dnsx to resolve A/AAAA in JSON mode:
      dnsx -a -aaaa -json -silent -rl <rate> -t <timeout> -retry <n>
      [-r 1.1.1.1,8.8.8.8 | -rf resolvers.txt]
    JSON line: {"host":"example.com","a":["1.2.3.4"],"aaaa":["2001:..."]}
    """
    if which(dnsx_path or "dnsx") is None or not domains:
        if not domains:
            return {}
        LOG.warning("[DNS] dnsx not found; using Python resolver")
        return resolve_domains_python(domains)

    rc, out, err = _dnsx_call_list(
        items=domains,
        base_args=["-a", "-aaaa", "-json"],
        dnsx_path=dnsx_path,
        resolvers=resolvers,
        resolvers_file=resolvers_file,
        dnsx_opts=dnsx_opts,
        label="DNS",
        rate=dnsx_rate,
        timeout_s=dnsx_timeout,
        retries=dnsx_retries,
        hard_timeout_sec=dnsx_hard_timeout
    )
    if rc != 0:
        LOG.warning("[DNS] dnsx rc=%s; stderr=%s ; using Python resolver", rc, (err or "")[:200])
        return resolve_domains_python(domains)

    mapping: Dict[str, Set[str]] = {d: set() for d in domains}
    n_json = 0
    for line in out.splitlines():
        try:
            obj = json.loads(line.strip())
        except Exception:
            continue
        host = str(obj.get("host") or "")
        if not host:
            continue
        ips: Set[str] = set()
        for key in ("a", "A", "aaaa", "AAAA"):
            vs = obj.get(key)
            if isinstance(vs, list):
                for ip in vs:
                    try:
                        ips.add(str(ipaddress.ip_address(str(ip))))
                    except Exception:
                        pass
        if ips:
            mapping.setdefault(host, set()).update(ips)
            n_json += 1
    LOG.info("[DNS] dnsx resolved %d/%d domains (json lines: %d)", sum(1 for s in mapping.values() if s), len(domains), n_json)

    if all(len(v) == 0 for v in mapping.values()):
        LOG.warning("[DNS] dnsx produced no parsed answers; using Python resolver")
        return resolve_domains_python(domains)

    return mapping

# ------------------- RDAP -------------------

def _sanitize(v: Optional[str]) -> str:
    if v is None:
        return ""
    s = str(v).strip()
    if s.lower() in {"na", "n/a", "none", "null"}:
        return ""
    return s

def rdap_lookup(ip: str) -> Tuple[Dict[str, str], str]:
    if IPWhois is None:
        return {"asn":"", "org":"", "country":"", "cidr":""}, "no_lib"
    try:
        data = IPWhois(ip).lookup_rdap(depth=1)
        asn = _sanitize(data.get("asn"))
        org = _sanitize(data.get("asn_description"))
        net = data.get("network") or {}
        cidr = _sanitize(net.get("cidr"))
        ctry = _sanitize(net.get("country")) or _sanitize(data.get("asn_country_code"))
        info = {"asn": asn, "org": org, "country": ctry, "cidr": cidr}
        status = "ok" if any(info.values()) else "empty"
        return info, status
    except Exception:
        return {"asn":"", "org":"", "country":"", "cidr":""}, "error"

def rdap_enrich(ips: List[str], cache_path: Path, sleep_between: float = 0.0,
                retries: int = 2, log_every: int = 200) -> Dict[str, Dict[str,str]]:
    t0 = time.time()
    cache: Dict[str, Dict[str,str]] = {}

    # Ensure the directory for the cache file exists (handles first run)
    try:
        ensure_dir(cache_path.parent)
    except Exception:
        pass

    if cache_path.exists():
        for ln in cache_path.read_text(encoding="utf-8", errors="ignore").splitlines():
            try:
                obj = json.loads(ln)
                ip = obj.get("ip")
                if ip:
                    cache[ip] = {
                        "asn": obj.get("asn",""), "org": obj.get("org",""),
                        "country": obj.get("country",""), "cidr": obj.get("cidr",""),
                        "rdap_status": obj.get("rdap_status","")
                    }
            except Exception:
                continue
    out: Dict[str, Dict[str,str]] = dict(cache)
    to_fetch = [ip for ip in ips if ip not in out]
    LOG.info("[RDAP] starting lookups for %d IPs (cached=%d, retries=%d, sleep=%.2fs)",
             len(to_fetch), len(cache), retries, sleep_between)
    for i, ip in enumerate(to_fetch, start=1):
        info = {"asn":"", "org":"", "country":"", "cidr":""}
        status = "error"
        for attempt in range(retries+1):
            info, status = rdap_lookup(ip)
            if status in {"ok","empty","no_lib"}:
                break
            time.sleep(0.3*(attempt+1))
        out[ip] = {**info, "rdap_status": status}
        with cache_path.open("a", encoding="utf-8") as f:
            f.write(json.dumps({"ip": ip, **out[ip]}) + "\n")
        if sleep_between > 0:
            time.sleep(sleep_between)
        if i % log_every == 0:
            LOG.debug("[RDAP] %d/%d done...", i, len(to_fetch))
    dt = time.time() - t0
    ok_count = sum(1 for v in out.values() if v.get("rdap_status") == "ok")
    LOG.info("[RDAP] complete in %.2fs; ok=%d, empty=%d, error=%d, no_lib=%d",
             dt,
             ok_count,
             sum(1 for v in out.values() if v.get("rdap_status") == "empty"),
             sum(1 for v in out.values() if v.get("rdap_status") == "error"),
             sum(1 for v in out.values() if v.get("rdap_status") == "no_lib"))
    return out

# ------------------- TCP probing -------------------

def _connect(ip: str, port: int, timeout: float) -> bool:
    family = socket.AF_INET6 if ":" in ip else socket.AF_INET
    s = socket.socket(family, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        return True
    except Exception:
        return False
    finally:
        try: s.close()
        except Exception: pass

def tcp_probe_ports(ips: List[str], ports: List[int], timeout: float = 1.0, workers: int = 200, log_every: int = 500) -> Dict[str, Set[int]]:
    LOG.info("[PROBE] starting TCP connect probes for %d IPs over %d ports (timeout=%.1fs, workers=%d)", len(ips), len(ports), timeout, workers)
    results: Dict[str, Set[int]] = {ip: set() for ip in ips}
    def _job(ip, p):
        return ip, p, _connect(ip, p, timeout)
    t0 = time.time()
    with cf.ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
        futs = [ex.submit(_job, ip, p) for ip in ips for p in ports]
        for i, fut in enumerate(cf.as_completed(futs), start=1):
            ip, p, ok = fut.result()
            if ok:
                results[ip].add(p)
            if i % log_every == 0:
                LOG.debug("[PROBE] %d/%d done...", i, len(futs))
    dt = time.time() - t0
    live = sum(1 for v in results.values() if v)
    LOG.info("[PROBE] complete in %.2fs; %d/%d IPs reported at least one open port (%.1f%%)",
             dt, live, len(ips), 100.0*live/max(1,len(ips)))
    return results

def http_probe(ip: str, port: int = 80, timeout: float = 1.0, use_tls: bool = False) -> str:
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        if use_tls:
            ctx = ssl.create_default_context()
            s = ctx.wrap_socket(s, server_hostname=ip)
        req = f"HEAD / HTTP/1.0\r\nHost: {ip}\r\nUser-Agent: ip-assets-enrich/1.0\r\n\r\n"
        s.sendall(req.encode("ascii", errors="ignore"))
        data = s.recv(4096).decode("latin1", errors="ignore")
        s.close()
        line = data.split("\r\n", 1)[0]
        return line[:80]
    except Exception:
        return ""

# ------------------- writers -------------------

def write_xlsx_with_asn_summary(path: Path, rows: List[Dict[str,str]], headers: List[str]) -> bool:
    try:
        import xlsxwriter
    except Exception:
        return False
    ensure_dir(path.parent)
    wb = xlsxwriter.Workbook(str(path))
    # Sheet 1: IPs
    ws = wb.add_worksheet("IPs")
    head = wb.add_format({"bold": True})
    for ci, h in enumerate(headers):
        ws.write(0, ci, h, head)
    for ri, row in enumerate(rows, start=1):
        for ci, h in enumerate(headers):
            ws.write(ri, ci, row.get(h,""))
    ws.autofilter(0, 0, len(rows), max(0, len(headers)-1))
    try: ws.freeze_panes(1, 0)
    except Exception: pass
    widths = {"ip":18, "hostname":42, "asn":10, "org":46, "country":8, "cidr":24, "source":14, "sources_count":14, "rdap_status":12,
              "domains":44, "domains_count":14, "is_live":8, "open_ports":16, "http_status":22}
    for ci, h in enumerate(headers):
        ws.set_column(ci, ci, widths.get(h, min(60, max(10, len(h)+2))))

    # Sheet 2: ASN_Summary
    by_asn: DefaultDict[Tuple[str,str,str], List[str]] = defaultdict(list)
    for r in rows:
        key = (r.get("asn",""), r.get("org",""), r.get("country",""))
        by_asn[key].append(r.get("ip",""))

    ws2 = wb.add_worksheet("ASN_Summary")
    ws2.write_row(0, 0, ["asn","org","country","ip_count","sample_ips"])
    r = 1
    for (asn, org, ctry), ip_list in sorted(by_asn.items(), key=lambda kv: (-len(kv[1]), kv[0][0])):
        sample = ", ".join(ip_list[:20])
        ws2.write_row(r, 0, [asn, org, ctry, len(ip_list), sample])
        r += 1
    ws2.autofilter(0, 0, r-1, 4)
    try: ws2.freeze_panes(1, 0)
    except Exception: pass
    ws2.set_column(0, 0, 12); ws2.set_column(1, 1, 60)
    ws2.set_column(2, 2, 10); ws2.set_column(3, 3, 12); ws2.set_column(4, 4, 80)

    wb.close()
    return True

# ------------------- main -------------------

def main():
    ap = argparse.ArgumentParser(description="Expand CIDRs & IPs, resolve domains, PTR + RDAP, optional TCP probes, XLSX/CSV (+ ASN summary, debug logs).")
    ap.add_argument("--input-file", help="Text file of CIDRs and/or IPs (one per line)")
    ap.add_argument("--inputs", nargs="*", default=[], help="Inline CIDRs/IPs if not using --input-file")
    ap.add_argument("--domains-file", help="Optional file of domains (one per line) to resolve to IPs")
    ap.add_argument("--output", required=True, help="Output path prefix (e.g., ./out/ip_assets)")

    # PTR & DNS
    ap.add_argument("--workers", type=int, default=64, help="Concurrent PTR lookups (Python mode)")
    ap.add_argument("--ptr-timeout", type=float, default=3.5, help="Socket timeout for PTR lookups (Python mode)")
    ap.add_argument("--dnsx", choices=["yes","no"], default="no", help="Use dnsx for DNS (PTR and domains) if available")
    ap.add_argument("--dnsx-path", default="dnsx", help="Path to dnsx binary")
    ap.add_argument("--resolvers", default="", help="Comma-separated DNS resolvers for dnsx (e.g. 1.1.1.1,8.8.8.8)")
    ap.add_argument("--resolvers-file", default=None, help="dnsx resolvers file (optional)")
    ap.add_argument("--dnsx-opts", default="", help="Additional flags passed to dnsx (optional)")
    ap.add_argument("--dnsx-rate", type=int, default=200, help="dnsx -rl rate limit (qps)")
    ap.add_argument("--dnsx-timeout", type=int, default=4, help="dnsx -t timeout (seconds)")
    ap.add_argument("--dnsx-retries", type=int, default=2, help="dnsx -retry count")
    ap.add_argument("--dnsx-hard-timeout", type=int, default=0,
                    help="Hard wall-clock timeout (seconds) for a single dnsx invocation. 0 = auto (scales with list size).")

    # RDAP
    ap.add_argument("--rdap-sleep", type=float, default=0.0, help="Sleep seconds between RDAP calls")
    ap.add_argument("--rdap-retries", type=int, default=2, help="Retries per RDAP lookup on error")

    # Probes
    ap.add_argument("--check-live", choices=["yes","no"], default="no", help="If 'yes', perform TCP liveness probes")
    ap.add_argument("--probe-ports", default="80,443,22", help="Comma-separated ports to probe when --check-live yes")
    ap.add_argument("--probe-timeout", type=float, default=1.0, help="Timeout per TCP connect attempt (seconds)")
    ap.add_argument("--probe-workers", type=int, default=200, help="Concurrency for TCP probes")

    # Logging
    ap.add_argument("--log", default="INFO", help="Log level: DEBUG, INFO, WARNING, ERROR")
    args = ap.parse_args()

    setup_logging(args.log)

    resolvers = [x.strip() for x in args.resolvers.split(",") if x.strip()] if args.resolvers else None
    if args.dnsx == "yes":
        LOG.info("[CFG] dnsx enabled; resolvers=%s resolvers_file=%s rate=%d t=%ds retry=%d hard_timeout=%s",
                 resolvers if resolvers else "(default)", args.resolvers_file or "(none)",
                 args.dnsx_rate, args.dnsx_timeout, args.dnsx_retries,
                 (args.dnsx_hard_timeout if args.dnsx_hard_timeout else "auto"))

    # Load IP/CIDR inputs
    seeds: List[str] = []
    if args.input_file:
        seeds += read_lines(Path(args.input_file))
    if args.inputs:
        seeds += list(args.inputs)

    ips, source_map = parse_targets(seeds)

    # Optional: domains -> IPs
    domain_to_ips: Dict[str, Set[str]] = {}
    ip_to_domains: defaultdict[str, Set[str]] = defaultdict(set)  # type: ignore
    domains: List[str] = []
    if args.domains_file:
        domains = parse_domains(read_lines(Path(args.domains_file)))
        if domains:
            if args.dnsx == "yes":
                domain_to_ips = resolve_domains_dnsx(
                    domains, args.dnsx_path, resolvers, args.resolvers_file,
                    args.dnsx_rate, args.dnsx_timeout, args.dnsx_retries,
                    args.dnsx_opts, args.dnsx_hard_timeout
                )
            else:
                domain_to_ips = resolve_domains_python(domains)
            # Build reverse map
            for dom, ipset in domain_to_ips.items():
                for ip in ipset:
                    ip_to_domains[ip].add(dom)
            # Merge resolved IPs into the set, preserving provenance
            for ip, domset in ip_to_domains.items():
                ips.add(ip)
                prev = set(source_map.get(ip, "").split(",")) if source_map.get(ip) else set()
                prev.add("domain_resolve")
                source_map[ip] = ",".join(sorted(x for x in prev if x))

    ips_sorted = sorted(ips, key=lambda s: (":" in s, s))  # IPv4 first
    LOG.info("[INIT] Unique IPs after expand/dedupe (+domain resolves): %d", len(ips_sorted))

    if not ips_sorted:
        LOG.warning("[INIT] No valid IPs to process.")
        return

    # PTR
    if args.dnsx == "yes":
        ptrs = ptr_lookup_dnsx(
            ips_sorted, args.dnsx_path, resolvers, args.resolvers_file,
            args.dnsx_rate, args.dnsx_timeout, args.dnsx_retries,
            args.dnsx_opts, args.dnsx_hard_timeout
        )
    else:
        ptrs = ptr_lookup_python(ips_sorted, workers=args.workers, timeout=args.ptr_timeout)

    # RDAP
    cache_path = Path(f"{args.output}_rdap_cache.jsonl")
    rdap = rdap_enrich(ips_sorted, cache_path, sleep_between=args.rdap_sleep, retries=args.rdap_retries)

    # Optional TCP liveness
    open_by_ip: Dict[str, Set[int]] = {}
    if args.check_live == "yes":
        try:
            ports = [int(x) for x in args.probe_ports.split(",") if x.strip()]
        except Exception:
            ports = [80,443,22]
        open_by_ip = tcp_probe_ports(ips_sorted, ports, timeout=args.probe_timeout, workers=args.probe_workers)

    # Build rows
    rows: List[Dict[str,str]] = []
    for ip in ips_sorted:
        info = rdap.get(ip, {}) or {}
        source = source_map.get(ip, "")
        doms = sorted(ip_to_domains.get(ip, set()))
        row = {
            "ip": ip,
            "hostname": ptrs.get(ip, ""),
            "asn": info.get("asn",""),
            "org": info.get("org",""),
            "country": info.get("country",""),
            "cidr": info.get("cidr",""),
            "source": source,
            "sources_count": str(source.count(",")+1) if source else "0",
            "rdap_status": info.get("rdap_status",""),
        }
        if domains:
            row["domains"] = ",".join(doms)
            row["domains_count"] = str(len(doms))
        if args.check_live == "yes":
            open_set = open_by_ip.get(ip, set())
            row["is_live"] = "yes" if open_set else "no"
            row["open_ports"] = ",".join(str(p) for p in sorted(open_set))
            http_line = ""
            if 80 in open_set:
                http_line = http_probe(ip, 80, timeout=1.0, use_tls=False)
            elif 443 in open_set:
                http_line = http_probe(ip, 443, timeout=1.0, use_tls=True)
            row["http_status"] = http_line
        rows.append(row)

    # Headers
    base_headers = ["ip","hostname","asn","org","country","cidr","source","sources_count","rdap_status"]
    if domains:
        base_headers += ["domains","domains_count"]
    if args.check_live == "yes":
        base_headers += ["is_live","open_ports","http_status"]
    headers = base_headers

    # Write outputs
    out_prefix = Path(args.output).resolve()
    csv_path = out_prefix.with_suffix(".csv")
    xlsx_path = out_prefix.with_suffix(".xlsx")

    ensure_dir(out_prefix.parent)
    with csv_path.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=headers)
        w.writeheader()
        w.writerows(rows)
    LOG.info("[WRITE] CSV: %s (rows=%d)", csv_path, len(rows))

    ok = write_xlsx_with_asn_summary(xlsx_path, rows, headers)
    if ok:
        LOG.info("[WRITE] XLSX: %s (rows=%d)", xlsx_path, len(rows))
    else:
        LOG.warning("[WRITE] xlsxwriter not installed; only CSV written.")

    LOG.info("[DONE] Complete.")

if __name__ == "__main__":
    main()

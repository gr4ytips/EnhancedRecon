#!/usr/bin/env python3
"""
org_to_roots_seedgen.py
-----------------------
Step 0 for black-box external testing:
Given organization names (and optional known domain hints), generate a high-confidence
list of apex/root domains suitable to feed into Step A of your pipeline.

Sources:
  - Heuristics from org names (no API needed)
  - crt.sh JSON (no API key)  -> hostnames -> reduced to apex
  - SecurityTrails keyword/company search (optional; needs SECURITYTRAILS_KEY)

Outputs:
  - roots.txt        : final deduped apex list
  - roots_map.csv    : "root,source_list" provenance per root
  - roots_raw.txt    : raw candidates before scoring/dedupe

Notes:
  - No subdomain enumeration or DNS resolution here (that’s B/C).
  - No IP/PTR/RDAP (that’s A/D).
"""

from __future__ import annotations
import argparse, json, os, re, sys, unicodedata, time
from pathlib import Path
from typing import List, Set, Dict, Iterable, Tuple, Optional
import urllib.request, urllib.parse

# ---------------- I/O helpers ----------------

def read_lines(p: Path) -> List[str]:
    if not p or not p.exists():
        return []
    out: List[str] = []
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

# ---------------- text/slug utils ----------------

_ORG_SUFFIXES = {
    "inc","inc.","llc","l.l.c.","ltd","ltd.","pty","pty.","pty ltd","plc","plc.","corp","corporation","company","co","co.",
    "co ltd","co.,ltd.","gmbh","ag","sa","sas","sarl","bv","oy","ab","k.k.","kk","pte","pte.","pte ltd","pte. ltd.",
    "s.p.a","spa","srl","oyj","as","aps","aps.","nv","bvba","kft","zrt","ooo","ooo.","oy","ab","s.a.","s.a",
    "limited","holdings","group","int","intl","international","solutions","systems","technologies","technology",
    "services","service"
}

def normalize_org(org: str) -> str:
    s = unicodedata.normalize("NFKD", org).encode("ascii", "ignore").decode("ascii")
    s = s.lower()
    s = re.sub(r"[’'`]", "", s)
    s = re.sub(r"[\(\)\[\]\{\}]", " ", s)
    s = re.sub(r"[-_/#&+,]", " ", s)
    s = re.sub(r"\s+", " ", s).strip()
    # drop suffix words
    parts = [w for w in s.split() if w not in _ORG_SUFFIXES]
    return " ".join(parts) if parts else s

def slug_variants(core: str) -> List[str]:
    # core like "acme solar"
    words = core.split()
    variants: Set[str] = set()
    if not words:
        return []
    # base
    base = "".join(words)
    variants.add(base)
    # hyphenated
    variants.add("-".join(words))
    # if more than 1 word: add compact corp-likes
    if len(words) >= 2:
        variants.add(words[0] + words[-1])          # acmesolar
        variants.add(words[0] + "-"+ words[-1])     # acme-solar
        # drop tiny words (like &/and/of)
        major = [w for w in words if len(w) > 2]
        if major:
            variants.add("".join(major))
            variants.add("-".join(major))
    # collapse doubles
    out = sorted({re.sub(r"[^a-z0-9\-]", "", v).strip("-") for v in variants if re.sub(r"[^a-z0-9\-]", "", v).strip("-")})
    return out

# ---------------- apex helpers ----------------

# very small public-suffix exceptions for correct eTLD+1 reduction
_TWO_LABEL_SUFFIXES = {
    "co.uk","org.uk","ac.uk","gov.uk","net.uk",
    "com.au","net.au","org.au","edu.au",
    "co.in","firm.in","net.in","org.in","gen.in","ind.in",
    "com.br","net.br","org.br",
    "co.nz","org.nz","govt.nz","ac.nz","net.nz",
    "com.mx","org.mx","net.mx",
    "com.tr","org.tr","net.tr",
    "com.sg","net.sg","org.sg",
    "com.hk","net.hk","org.hk",
    "com.tw","net.tw","org.tw",
    "co.jp","ne.jp","or.jp",
    "com.cn","net.cn","org.cn"
}

def to_apex(host: str) -> Optional[str]:
    h = host.lower().strip().strip(".")
    if not h or "." not in h:
        return None
    # if it contains space or protocol, discard
    if " " in h or "://" in h:
        return None
    parts = h.split(".")
    if len(parts) < 2:
        return None
    tail2 = ".".join(parts[-2:])
    tail3 = ".".join(parts[-3:])
    if tail3 in _TWO_LABEL_SUFFIXES:
        # e.g., a.b.co.uk -> b.co.uk
        return ".".join(parts[-4:]) if len(parts) >= 4 else None
    if tail2 in _TWO_LABEL_SUFFIXES:
        return ".".join(parts[-3:]) if len(parts) >= 3 else None
    # If last 2 labels equals a known 2-label suffix, capture three labels, else use last 2
    if any(tail2.endswith(suf) for suf in _TWO_LABEL_SUFFIXES):
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])

# ---------------- web fetch ----------------

def http_json(url: str, headers: Dict[str,str] | None = None, timeout: float = 12.0) -> Optional[object]:
    req = urllib.request.Request(url, headers=headers or {"User-Agent":"orgseed/1.0"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = resp.read()
            ct = resp.headers.get("Content-Type","")
            if "application/json" in ct or data.strip().startswith(b"[") or data.strip().startswith(b"{"):
                return json.loads(data.decode("utf-8","ignore"))
            return None
    except Exception as e:
        if os.environ.get("ORGSEED_DEBUG") == "1":
            print(f"[crtsh] fetch error: {e!r} url={url}", file=sys.stderr)
        return None


# ---------------- collectors ----------------

def candidates_from_heuristics(orgs: List[str], tlds: List[str], cc_suffixes: List[str]) -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {}
    for org in orgs:
        core = normalize_org(org)
        if not core:
            continue
        for slug in slug_variants(core):
            for t in tlds:
                out.setdefault(f"{slug}.{t}", set()).add("heuristic")
            for suf in cc_suffixes:
                out.setdefault(f"{slug}.{suf}", set()).add("heuristic")
    return out

def candidates_from_known_domains(domains: List[str]) -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {}
    for d in domains:
        apex = to_apex(d)
        if apex:
            out.setdefault(apex, set()).add("hint")
    return out

def candidates_from_crtsh(orgs: List[str], max_hosts_per_org: int = 2000) -> Dict[str, Set[str]]:
    out: Dict[str, Set[str]] = {}

    # Build a small unique query set to avoid hammering crt.sh with near-duplicates
    query_terms = set()
    for org in orgs:
        core = normalize_org(org)
        if not core:
            continue
        # prefer first token (e.g., "fidelity") rather than long legal names
        query_terms.add(core.split()[0])

    for term in sorted(query_terms):
        q = urllib.parse.quote(f"%{term}%")
        url = f"https://crt.sh/?q={q}&exclude=expired&output=json"
        data = http_json(url, timeout=120.0)
        if not isinstance(data, list):
            continue

        count = 0
        for rec in data:
            if not isinstance(rec, dict):
                continue
            namev = rec.get("name_value") or ""
            if not namev:
                continue
            for raw in str(namev).splitlines():
                h = raw.strip().lower()
                if not h:
                    continue
                if h.startswith("*."):
                    h = h[2:]
                apex = to_apex(h)
                if apex:
                    out.setdefault(apex, set()).add("crtsh")
                    count += 1
                    if count >= max_hosts_per_org:
                        break
            if count >= max_hosts_per_org:
                break
        time.sleep(0.4)
    return out


def candidates_from_securitytrails(orgs: List[str], key: Optional[str]) -> Dict[str, Set[str]]:
    """
    Very lightweight ST keyword search. Requires SECURITYTRAILS_KEY.
    We query /v1/domains/list?include_ips=false&filter=... for each org word.
    """
    if not key:
        return {}
    headers = {"APIKEY": key, "User-Agent":"orgseed/1.0"}
    out: Dict[str, Set[str]] = {}
    for org in orgs:
        core = normalize_org(org)
        if not core:
            continue
        # try a couple of filters: query=core and query=first_word
        queries = [core]
        first = core.split()[0] if core.split() else ""
        if first and first != core:
            queries.append(first)
        for q in queries:
            url = f"https://api.securitytrails.com/v1/domains/list?include_ips=false&query={urllib.parse.quote(q)}"
            data = http_json(url, headers=headers, timeout=15.0)
            if isinstance(data, dict):
                # try common result layouts
                lists = []
                for k in ("records","domains","items","result"):
                    v = data.get(k)
                    if isinstance(v, list):
                        lists.append(v)
                    elif isinstance(v, dict):
                        vv = v.get("items") or v.get("domains") or v.get("records")
                        if isinstance(vv, list):
                            lists.append(vv)
                for L in lists:
                    for item in L:
                        dom = None
                        if isinstance(item, str):
                            dom = item
                        elif isinstance(item, dict):
                            dom = item.get("hostname") or item.get("domain") or item.get("name")
                        if dom:
                            apex = to_apex(str(dom))
                            if apex:
                                out.setdefault(apex, set()).add("securitytrails")
        time.sleep(0.3)
    return out

# ---------------- scoring / selection ----------------

def score_roots(root_to_sources: Dict[str, Set[str]]) -> List[Tuple[str, int, str]]:
    """
    Score roots by source diversity then lexicographically.
    Heuristic: more sources => more confidence.
    """
    scored = []
    for r, srcs in root_to_sources.items():
        score = len(srcs)
        scored.append((r, score, ",".join(sorted(srcs))))
    scored.sort(key=lambda t: (-t[1], t[0]))
    return scored

# ---------------- main ----------------

_DEFAULT_TLDS = "com,net,org,io,ai,app,co,dev,cloud,tech,us,xyz"
_DEFAULT_CC_SUFFIXES = "co.uk,com.au,co.in,com.br,co.nz,com.mx,com.tr,com.sg,com.hk,com.tw,co.jp,com.cn"

def main():
    ap = argparse.ArgumentParser(description="Generate apex/root domains from organization names (Step 0 seed generator).")
    ap.add_argument("--orgs-file", required=True, help="Text file with organization names (one per line)")
    ap.add_argument("--known-domains-file", default="", help="Optional hints: known domains to incorporate")
    ap.add_argument("--out-dir", required=True, help="Output directory")
    ap.add_argument("--tlds", default=_DEFAULT_TLDS, help=f"Comma TLDs (default: {_DEFAULT_TLDS})")
    ap.add_argument("--cc-suffixes", default=_DEFAULT_CC_SUFFIXES, help=f"Comma ccTLD suffixes (default: {_DEFAULT_CC_SUFFIXES})")
    ap.add_argument("--use-crtsh", choices=["yes","no"], default="yes", help="Query crt.sh JSON to harvest candidate roots")
    ap.add_argument("--use-securitytrails", choices=["auto","yes","no"], default="auto", help="Use SecurityTrails if SECURITYTRAILS_KEY present")
    ap.add_argument("--max-roots", type=int, default=2000, help="Cap final roots (highest score first)")
    ap.add_argument("--log-every", type=int, default=200, help="Progress pulse for large org lists")
    args = ap.parse_args()

    out_dir = Path(args.out_dir).expanduser().resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    orgs = read_lines(Path(args.orgs_file).expanduser().resolve())
    if not orgs:
        print(f"ERROR: no orgs in {args.orgs_file}", file=sys.stderr)
        sys.exit(2)

    known_domains = read_lines(Path(args.known_domains_file).expanduser().resolve()) if args.known_domains_file else []

    tlds = [t.strip().lower() for t in args.tlds.split(",") if t.strip()]
    cc_suffixes = [t.strip().lower() for t in args.cc_suffixes.split(",") if t.strip()]

    print(f"[0] Orgs: {len(orgs)}  TLDs: {len(tlds)}  cc-suffixes: {len(cc_suffixes)}")
    if known_domains:
        print(f"[0] Known-domain hints: {len(known_domains)}")

    # Collect candidates by source
    merged: Dict[str, Set[str]] = {}

    # Heuristics
    h = candidates_from_heuristics(orgs, tlds, cc_suffixes)
    for k,v in h.items(): merged.setdefault(k, set()).update(v)
    print(f"[0] Heuristic candidates: {len(h)}")

    # Known domain hints
    kd = candidates_from_known_domains(known_domains)
    for k,v in kd.items(): merged.setdefault(k, set()).update(v)
    if kd:
        print(f"[0] From hints: {len(kd)}")

    # crt.sh
    if args.use_crtsh == "yes":
        cr = candidates_from_crtsh(orgs)
        for k,v in cr.items(): merged.setdefault(k, set()).update(v)
        print(f"[0] crt.sh candidates: {len(cr)}")

    # SecurityTrails (optional)
    st_key = (os.environ.get("SECURITYTRAILS_KEY") or "").strip() or None
    use_st = (args.use_securitytrails == "yes") or (args.use_securitytrails == "auto" and st_key)
    if use_st and st_key:
        st = candidates_from_securitytrails(orgs, st_key)
        for k,v in st.items(): merged.setdefault(k, set()).update(v)
        print(f"[0] SecurityTrails candidates: {len(st)}")
    elif args.use_securitytrails == "yes" and not st_key:
        print("[0] SecurityTrails explicitly enabled but SECURITYTRAILS_KEY not set; skipping.", file=sys.stderr)

    # Save raw
    roots_raw = sorted(merged.keys())
    write_lines(out_dir / "roots_raw.txt", roots_raw)

    # Score + cap
    scored = score_roots(merged)
    if args.max_roots and len(scored) > args.max_roots:
        scored = scored[:args.max_roots]

    # Write map + final
    map_rows = ["root,source_list"]
    final_roots: List[str] = []
    for root, score, srcs in scored:
        final_roots.append(root)
        map_rows.append(f"{root},{srcs}")
    write_lines(out_dir / "roots_map.csv", map_rows)
    write_lines(out_dir / "roots.txt", final_roots)

    print(f"[0] Final roots: {len(final_roots)}  -> {out_dir/'roots.txt'}")
    print(f"[0] Map CSV    : {out_dir/'roots_map.csv'}")
    if not final_roots:
        print("WARN: No roots produced. Try adding more TLDs/cc-suffixes or enable crt.sh/SecurityTrails.", file=sys.stderr)

if __name__ == "__main__":
    main()

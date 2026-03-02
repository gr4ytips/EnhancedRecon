#!/usr/bin/env python3
"""
phase3_truth_http.py — Phase 3 "truth layer" (safe HTTP validation)

Enhancements vs prior version:
  - Reuse ONE httpx.AsyncClient per domain run (keeps keep-alive / connection pooling)
  - --resume: skip URLs already present in http_truth.jsonl (append mode)
  - Stream JSONL incrementally (no "results = []" accumulation)

Safety / scope:
  - Allowed file is treated as EXACT hosts only (no suffix expansion).
  - Redirects are only followed when the redirect target hostname is ALSO in allowed.
  - Default method is HEAD; falls back to GET only when needed.
  - No crawling; no parameter brute force; only validates existing URLs.

Outputs per domain:
  <domain>/analysis/truth/http_truth.jsonl
  <domain>/analysis/truth/http_truth_summary.csv
"""

from __future__ import annotations

import argparse
import csv
import json
import re
import sys
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlparse, urlunparse

DEBUG = True

WAYBACK_RX = re.compile(r"^https?://web\.archive\.org/web/\d+(?:[a-z_]+)?/(.+)$", re.I)


def dbg(msg: str) -> None:
    if DEBUG:
        print(f"[phase3_truth] {msg}", file=sys.stderr)


def read_lines(p: Path) -> list[str]:
    if not p.exists():
        return []
    return [ln.strip() for ln in p.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip()]


def read_allowed(file: Path) -> set[str]:
    out: set[str] = set()
    if not file or not file.exists():
        return out
    for ln in read_lines(file):
        if ln.startswith("#"):
            continue
        h = ln.strip().lower().rstrip(".")
        if h:
            out.add(h)
    return out


def unwrap_wayback(u: str) -> str:
    if not u:
        return u
    m = WAYBACK_RX.match(u.strip())
    if not m:
        return u.strip()
    inner = (m.group(1) or "").strip()
    if inner.startswith("//"):
        return "https:" + inner
    return inner


def normalize_url(u: str) -> str:
    """Normalize URL minimally for dedupe/resume: strip fragment, lowercase host, keep query."""
    u = unwrap_wayback(u)
    try:
        p = urlparse(u)
    except Exception:
        return u
    if not p.scheme or not p.netloc:
        return u
    p2 = p._replace(fragment="")

    host = (p2.hostname or "").lower().rstrip(".")
    if not host:
        return u

    netloc = host
    if p2.port:
        netloc = f"{host}:{p2.port}"

    if p2.username:
        userinfo = p2.username
        if p2.password:
            userinfo += ":" + p2.password
        netloc = f"{userinfo}@{netloc}"

    p2 = p2._replace(netloc=netloc)
    return urlunparse(p2)


def url_key(u: str) -> tuple[str, str, tuple[str, ...]]:
    """(host, path, sorted query keys)"""
    try:
        p = urlparse(u)
    except Exception:
        return ("", "/", tuple())
    host = (p.hostname or "").lower().rstrip(".")
    path = p.path or "/"
    qk = tuple(sorted([k for k, _ in parse_qsl(p.query, keep_blank_values=True)]))
    return (host, path, qk)


def in_scope(u: str, allowed: set[str]) -> bool:
    try:
        h = (urlparse(u).hostname or "").lower().rstrip(".")
    except Exception:
        return False
    return (not allowed) or (h in allowed)


def gather_urls(ddir: Path) -> list[str]:
    analysis = ddir / "analysis"
    candidates = [
        analysis / "live" / "live_urls.txt",
        analysis / "katana_urls.txt",
        analysis / "rendered_endpoints_urls.txt",
        analysis / "unique_parameters.txt",
        analysis / "paramspider_params.txt",
    ]
    urls: list[str] = []
    for fp in candidates:
        if not fp.exists():
            continue
        for ln in read_lines(fp):
            u = ln.split()[0]
            if u.startswith("http"):
                urls.append(u)

    seen: set[str] = set()
    out: list[str] = []
    for u in urls:
        nu = normalize_url(u)
        if nu in seen:
            continue
        seen.add(nu)
        out.append(nu)
    return out


def should_follow_redirect(next_url: str, allowed: set[str]) -> bool:
    if not next_url:
        return False
    try:
        h = (urlparse(next_url).hostname or "").lower().rstrip(".")
    except Exception:
        return False
    return (not allowed) or (h in allowed)


def load_resume_set(jsonl: Path) -> set[str]:
    """Return normalized URLs already present in existing JSONL."""
    done: set[str] = set()
    if not jsonl.exists():
        return done
    for ln in jsonl.read_text(encoding="utf-8", errors="ignore").splitlines():
        ln = ln.strip()
        if not ln:
            continue
        try:
            obj = json.loads(ln)
        except Exception:
            continue
        u = obj.get("url")
        if isinstance(u, str) and u:
            done.add(normalize_url(u))
    return done


def write_csv_from_jsonl(jsonl: Path, out_csv: Path) -> None:
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    with out_csv.open("w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["url", "method", "status_code", "final_url", "error"])
        if not jsonl.exists():
            return
        for ln in jsonl.read_text(encoding="utf-8", errors="ignore").splitlines():
            ln = ln.strip()
            if not ln:
                continue
            try:
                obj = json.loads(ln)
            except Exception:
                continue
            w.writerow([
                obj.get("url") or "",
                obj.get("method") or "",
                obj.get("status_code") if obj.get("status_code") is not None else "",
                obj.get("final_url") or "",
                obj.get("error") or "",
            ])


async def run_async(domain_dir: Path, allowed: set[str], concurrency: int, timeout_s: float, max_urls: int, resume: bool) -> None:
    try:
        import asyncio
        import httpx  # type: ignore
    except Exception:
        raise SystemExit("httpx is required for phase3_truth_http.py (pip install httpx)")

    urls = [u for u in gather_urls(domain_dir) if in_scope(u, allowed)]
    if max_urls > 0:
        urls = urls[:max_urls]

    out_dir = domain_dir / "analysis" / "truth"
    out_dir.mkdir(parents=True, exist_ok=True)
    out_jsonl = out_dir / "http_truth.jsonl"
    out_csv = out_dir / "http_truth_summary.csv"

    already_done: set[str] = set()
    if resume:
        already_done = load_resume_set(out_jsonl)
        if already_done:
            dbg(f"{domain_dir.name}: resume enabled; {len(already_done)} URLs already present")

    if already_done:
        urls = [u for u in urls if normalize_url(u) not in already_done]

    jsonl_mode = "a" if (resume and out_jsonl.exists()) else "w"

    sem = asyncio.Semaphore(concurrency)

    limits = httpx.Limits(max_connections=concurrency, max_keepalive_connections=concurrency)
    timeout = httpx.Timeout(timeout_s)
    headers = {"User-Agent": "ReconAutomation/phase3_truth (safe)"}

    q: "asyncio.Queue[dict[str, Any] | None]" = asyncio.Queue()

    async def writer() -> int:
        written = 0
        with out_jsonl.open(jsonl_mode, encoding="utf-8") as f:
            while True:
                item = await q.get()
                if item is None:
                    break
                f.write(json.dumps(item, ensure_ascii=False) + "\n")
                written += 1
                if written % 200 == 0:
                    f.flush()
        return written

    async def fetch_one(client: "httpx.AsyncClient", u: str) -> None:
        async with sem:
            ts = int(time.time())
            chain: list[dict[str, Any]] = []
            method_used = "HEAD"
            status_code = None
            final_url = u
            err = ""

            try:
                r = await client.request("HEAD", u)
                status_code = r.status_code
                final_url = str(r.url)
                chain.append({"url": u, "status": r.status_code, "method": "HEAD"})

                redirect_hops = 0
                while r.is_redirect and redirect_hops < 5:
                    loc = r.headers.get("location") or ""
                    if not loc:
                        break
                    nxt = str(r.url.join(loc))
                    if not should_follow_redirect(nxt, allowed):
                        break
                    r = await client.request("HEAD", nxt)
                    final_url = str(r.url)
                    status_code = r.status_code
                    chain.append({"url": nxt, "status": r.status_code, "method": "HEAD"})
                    redirect_hops += 1

                if status_code in (405, 501) or status_code is None:
                    method_used = "GET"
                    r = await client.request("GET", u)
                    status_code = r.status_code
                    final_url = str(r.url)
                    chain.append({"url": u, "status": r.status_code, "method": "GET"})
            except Exception as e:
                err = str(e)

            host, path, qk = url_key(u)
            obj: dict[str, Any] = {
                "ts": ts,
                "domain_folder": domain_dir.name,
                "url": u,
                "host": host,
                "path": path,
                "query_keys": list(qk),
                "method": method_used,
                "status_code": status_code,
                "final_url": final_url,
                "redirect_chain": chain,
                "error": err,
            }
            await q.put(obj)

    writer_task = asyncio.create_task(writer())

    async with httpx.AsyncClient(timeout=timeout, follow_redirects=False, limits=limits, headers=headers) as client:
        tasks = [asyncio.create_task(fetch_one(client, u)) for u in urls]
        if tasks:
            await asyncio.gather(*tasks)

    await q.put(None)
    written = await writer_task

    write_csv_from_jsonl(out_jsonl, out_csv)
    dbg(f"{domain_dir.name}: wrote {out_jsonl} (+{written} rows this run)")


def main() -> None:
    ap = argparse.ArgumentParser(description="Phase-3 HTTP truth layer (safe validation)")
    ap.add_argument("--root", required=True, help="Phase-2 output root with per-domain folders")
    ap.add_argument("--allowed", required=True, help="Allowed EXACT hosts file (one per line)")
    ap.add_argument("--domain-filter", default="", help="Optional regex to further narrow selected folders")
    ap.add_argument("--concurrency", type=int, default=8, help="Max concurrent requests")
    ap.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout (seconds)")
    ap.add_argument("--max-urls", type=int, default=0, help="Max URLs per domain (0 = no limit)")
    ap.add_argument("--resume", action="store_true", help="Append + skip URLs already present in http_truth.jsonl")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    if not root.exists():
        print(f"root not found: {root}", file=sys.stderr)
        raise SystemExit(2)

    allowed = read_allowed(Path(args.allowed))
    if not allowed:
        print("allowed file is empty or missing", file=sys.stderr)
        raise SystemExit(2)

    R = re.compile(args.domain_filter, re.I) if args.domain_filter else None

    domains: list[Path] = []
    for d in sorted(root.iterdir()):
        if not d.is_dir():
            continue
        name = d.name.lower().rstrip(".")
        if name not in allowed:
            continue
        if R and not R.search(d.name):
            continue
        domains.append(d)

    if not domains:
        print("no per-domain folders matched scope", file=sys.stderr)
        return

    import asyncio
    for ddir in domains:
        print(f"\n[phase3_truth] >>> {ddir.name}")
        asyncio.run(run_async(ddir, allowed, args.concurrency, args.timeout, args.max_urls, args.resume))
        print(f"[phase3_truth] <<< {ddir.name}")

    print("\n[phase3_truth] done")


if __name__ == "__main__":
    main()

# post_scanners.py
from __future__ import annotations
import os, re, json, shutil, subprocess
from pathlib import Path
from typing import List, Optional, Tuple

import logging
log = logging.getLogger("phase2")

def _which(p: Optional[str]) -> Optional[str]:
    if not p:
        return None
    w = shutil.which(p)
    if w:
        return w
    try:
        pp = Path(p)
        if pp.exists():
            return str(pp)
    except Exception:
        pass
    return None

def _run(cmd: List[str], timeout: int) -> Tuple[int, str, str]:
    try:
        cp = subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, check=False)
        return cp.returncode, cp.stdout or "", cp.stderr or ""
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", f"exec error: {e}"

def _read_lines(p: Path) -> List[str]:
    if not p or not p.exists():
        return []
    out = []
    for s in p.read_text(encoding="utf-8", errors="ignore").splitlines():
        s = s.strip()
        if s:
            out.append(s)
    return out

JUICY_RE = re.compile(r'/(login|signin|admin|wp-admin|wp-login|oauth|account|api)(/|$)', re.I)

def _ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def _read_tags_file(p) -> list[str]:
    try:
        return [s.strip() for s in Path(p).read_text(encoding="utf-8", errors="ignore").splitlines() if s.strip()]
    except Exception:
        return []

def _read_lines_strip(path: Path) -> list[str]:
    try:
        return [s.strip() for s in path.read_text(encoding="utf-8", errors="ignore").splitlines() if s.strip()]
    except Exception:
        return []

def _merge_tags(base_csv: str, extra_list: list[str]) -> str:
    base = [t.strip().lower() for t in (base_csv or "").split(",") if t.strip()]
    seen = set()
    merged: list[str] = []
    # keep base order first, then extras
    for t in base + [e.strip().lower() for e in (extra_list or [])]:
        if not t or t in seen:
            continue
        # keep short, safe tokens only
        if len(t) <= 24 and re.fullmatch(r"[a-z0-9._-]+", t):
            merged.append(t)
            seen.add(t)
    return ",".join(merged)


def run_post_scanners(
    outdir: Path,
    alive_file: Path,
    interesting_file: Path,
    timeout_s: int = 600,
    max_targets: int = 500,

    # WhatWeb
    whatweb_bin: Optional[str] = None,

    # Nuclei
    nuclei_bin: Optional[str] = None,
    nuclei_templates: Optional[str] = None,
    nuclei_rate: float = 2.0,
    nuclei_concurrency: int = 50,
    nuclei_severity: str = "low,medium,high,critical",
    nuclei_tags: str = "cves,exposure,misconfig,tech",
    nuclei_extra_tags: Optional[Path] = None,

    # Nikto
    nikto_bin: Optional[str] = None,

    # Wapiti
    wapiti_bin: Optional[str] = None,
    wapiti_modules: str = "xss,sql,ssrf",
    wapiti_strength: str = "normal",

    # ZAP (headless)
    zap_baseline: Optional[str] = None,   # path to zap-baseline.py
    zap_full: Optional[str] = None,       # path to zap-full-scan.py
    zap_active_minutes: int = 5,
    zap_max_targets: int = 10,

    # Arachni
    arachni_bin: Optional[str] = None,
    arachni_max_targets: int = 5,

    # Skipfish
    skipfish_bin: Optional[str] = None,
    skipfish_wordlist: Optional[str] = None,
    skipfish_max_targets: int = 10,
):
    """
    Phase-2 Post-analysis online scanners. Each tool is optional and skipped if not found.
    Order:
      WhatWeb -> Nuclei -> Nikto/Wapiti -> ZAP/Arachni/Skipfish (curated targets only)
    Inputs:
      - alive_file: analysis/live/alive_urls.txt
      - interesting_file: analysis/interesting.txt
    Outputs under <outdir>/scanners/
    """
    outdir = Path(outdir)
    scanners_dir = outdir / "scanners"
    _ensure_dir(scanners_dir)

    alive_urls = _read_lines(alive_file)
    juicy_urls = []
    if interesting_file and interesting_file.exists():
        # interesting.txt can contain extra columns; take the first token that looks like a URL
        for line in _read_lines(interesting_file):
            u = line.split()[0]
            if u.startswith("http"):
                juicy_urls.append(u)

    # Deduplicate & cap
    def _dedupe_cap(lst: List[str], cap: int) -> List[str]:
        seen, out = set(), []
        for x in lst:
            if x not in seen:
                seen.add(x); out.append(x)
            if len(out) >= cap:
                break
        return out

    alive_urls = _dedupe_cap(alive_urls, max_targets)
    # curated heavy targets from interesting list (match JUICY_RE)
    curated = [u for u in juicy_urls if JUICY_RE.search(u)]
    curated = _dedupe_cap(curated, max(zap_max_targets, arachni_max_targets, skipfish_max_targets, 10))

    log.info("scanners: %d alive targets, %d curated heavy targets", len(alive_urls), len(curated))

    # ---------- WhatWeb ----------
    wweb = _which(whatweb_bin)
    if wweb and alive_urls:
        inp = scanners_dir / "whatweb_targets.txt"
        out_json = scanners_dir / "whatweb.json"
        inp.write_text("\n".join(alive_urls) + "\n", encoding="utf-8")
        cmd = [wweb, "--color=never", "--log-json", str(out_json), "--input-file", str(inp)]
        rc, out, err = _run(cmd, timeout_s)
        if rc in (0, 1) and out_json.exists():  # whatweb often returns 1 when findings exist
            log.info("scanners: whatweb -> %s", out_json)
        elif rc == 124:
            log.warning("scanners: whatweb timed out after %ss", timeout_s)
        else:
            log.warning("scanners: whatweb exited %s (%s)", rc, err.strip())
    else:
        log.info("scanners: whatweb not configured or no alive urls; skipping")

    # ---------- Nuclei ----------
    nuc = _which(nuclei_bin)
    if nuc and alive_urls and nuclei_templates:
        inp = scanners_dir / "nuclei_targets.txt"
        out_ndjson = scanners_dir / "nuclei.ndjson"
        cmd_log = scanners_dir / "nuclei_cmd.txt"
        inp.write_text("\n".join(alive_urls) + "\n", encoding="utf-8")

        # OPTIONAL tech-aware tags:
        # 1) prefer an explicitly-passed hints file (if your caller provides it)
        # 2) else auto-discover the default offline hints file
        extra_tags_file: Optional[Path] = None
        try:
            if "nuclei_extra_tags" in locals() and nuclei_extra_tags:
                p = Path(nuclei_extra_tags)
                if p.exists():
                    extra_tags_file = p
        except Exception:
            pass
        if not extra_tags_file:
            auto_hints = outdir / "analysis" / "offline" / "tech_hints.txt"
            if auto_hints.exists():
                extra_tags_file = auto_hints

        # Merge base tags + extra tech hints (if any)
        tags_arg = nuclei_tags
        if extra_tags_file:
            tech_tags = _read_lines_strip(extra_tags_file)
            if tech_tags:
                tags_arg = _merge_tags(nuclei_tags, tech_tags)
                log.info("scanners: nuclei tech-aware tags => %s", tags_arg)

        # Auto-tune max-host-error to avoid the warning and reduce stalls
        auto_mhe = max(10, min(200, int(nuclei_concurrency)))  # conservative cap

        cmd = [
            nuc,
            "-silent",
            "-rl", str(nuclei_rate),
            "-c", str(nuclei_concurrency),
            "-mhe", str(auto_mhe),
            "-severity", nuclei_severity,
            "-tags", tags_arg,
            "-t", nuclei_templates,
            "-l", str(inp),
            "-jsonl",
            "-o", str(out_ndjson),
        ]

        # log the exact command for reproducibility
        try:
            cmd_log.write_text(" ".join(map(str, cmd)) + "\n", encoding="utf-8")
        except Exception:
            pass

        rc, out, err = _run(cmd, timeout_s)
        if rc in (0, 1, 2) and out_ndjson.exists():
            log.info("scanners: nuclei -> %s", out_ndjson)
        elif rc == 124:
            log.warning("scanners: nuclei timed out after %ss", timeout_s)
        else:
            log.warning("scanners: nuclei exited %s (%s)", rc, err.strip())
    else:
        log.info("scanners: nuclei not configured/templates missing or no alive urls; skipping")

    # ---------- Nikto (curated) ----------
    nik = _which(nikto_bin)
    if nik and curated:
        out_txt = scanners_dir / "nikto.txt"
        with out_txt.open("a", encoding="utf-8") as fh:
            for u in curated:
                rc, out, err = _run([nik, "-ssl", "-nointeractive", "-host", u], min(timeout_s, 900))
                # nikto writes to stdout
                if out:
                    fh.write(out if out.endswith("\n") else out + "\n")
        log.info("scanners: nikto -> %s", out_txt)
    else:
        log.info("scanners: nikto not configured or no curated targets; skipping")

    # ---------- Wapiti (curated) ----------
    wap = _which(wapiti_bin)
    if wap and curated:
        base = scanners_dir / "wapiti"
        _ensure_dir(base)
        for u in curated:
            h = f"{abs(hash(u)) & 0xffffffff:08x}"
            o = base / h
            _ensure_dir(o)
            cmd = [wap, "-u", u, "-m", wapiti_modules, "-S", wapiti_strength, "-f", "json", "-o", str(o / "report.json")]
            rc, out, err = _run(cmd, min(timeout_s, 1800))
            if rc == 124:
                log.warning("scanners: wapiti timed out for %s", u)
        log.info("scanners: wapiti -> %s", base)
    else:
        log.info("scanners: wapiti not configured or no curated targets; skipping")

    # ---------- ZAP (baseline + optional full) ----------
    zapb = _which(zap_baseline)
    zapf = _which(zap_full)
    if zapb and curated:
        zap_dir = scanners_dir / "zap"
        _ensure_dir(zap_dir)
        for u in curated[:zap_max_targets]:
            h = f"{abs(hash(u)) & 0xffffffff:08x}"
            rep = zap_dir / f"baseline_{h}.html"
            cmd = [zapb, "-t", u, "-r", str(rep)]
            rc, out, err = _run(cmd, min(timeout_s, 1800))
            if rc == 124:
                log.warning("scanners: zap-baseline timed out for %s", u)
        log.info("scanners: zap-baseline -> %s", zap_dir)

        if zapf:
            for u in curated[:zap_max_targets]:
                h = f"{abs(hash(u)) & 0xffffffff:08x}"
                rep = zap_dir / f"full_{h}.html"
                # -m minutes (active scan duration)
                cmd = [zapf, "-t", u, "-m", str(zap_active_minutes), "-r", str(rep)]
                rc, out, err = _run(cmd, min(timeout_s, 3600))
                if rc == 124:
                    log.warning("scanners: zap-full timed out for %s", u)
            log.info("scanners: zap-full -> %s", zap_dir)
    else:
        log.info("scanners: ZAP not configured or no curated targets; skipping")

    # ---------- Arachni (curated) ----------
    ara = _which(arachni_bin)
    if ara and curated:
        a_dir = scanners_dir / "arachni"
        _ensure_dir(a_dir)
        for u in curated[:arachni_max_targets]:
            h = f"{abs(hash(u)) & 0xffffffff:08x}"
            out_json = a_dir / f"arachni_{h}.json"
            cmd = [ara, u, f"--reporter=json:outfile={out_json}"]
            rc, out, err = _run(cmd, min(timeout_s, 3600))
            if rc == 124:
                log.warning("scanners: arachni timed out for %s", u)
        log.info("scanners: arachni -> %s", a_dir)
    else:
        log.info("scanners: arachni not configured or no curated targets; skipping")

    # ---------- Skipfish (sample of alive) ----------
    sk = _which(skipfish_bin)
    if sk and alive_urls:
        sf_dir = scanners_dir / "skipfish"
        _ensure_dir(sf_dir)
        for u in alive_urls[:skipfish_max_targets]:
            h = f"{abs(hash(u)) & 0xffffffff:08x}"
            out_dir = sf_dir / f"sf_{h}"
            _ensure_dir(out_dir)
            cmd = [sk, "-o", str(out_dir)]
            if skipfish_wordlist:
                cmd += ["-W", skipfish_wordlist]
            cmd += [u]
            rc, out, err = _run(cmd, min(timeout_s, 1800))
            if rc == 124:
                log.warning("scanners: skipfish timed out for %s", u)
        log.info("scanners: skipfish -> %s", sf_dir)
    else:
        log.info("scanners: skipfish not configured or no alive urls; skipping")

    log.info("scanners: completed")

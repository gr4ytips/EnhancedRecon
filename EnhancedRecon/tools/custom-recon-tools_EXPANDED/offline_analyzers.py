# offline_analyzers.py
from __future__ import annotations
import logging, shutil, subprocess, threading, socket, re, json, time
from pathlib import Path
from typing import List, Optional, Tuple
from http.server import ThreadingHTTPServer, SimpleHTTPRequestHandler
from functools import partial
import csv


log = logging.getLogger("phase2")

# ---------- helpers ----------

def _emit_tech_hints(off_dir: Path) -> Optional[Path]:
    """
    Read WhatWeb/Wappalyzer/heuristics outputs and emit a tiny tag list
    that we can feed into Nuclei (-tags …) downstream.
    Output: <outdir>/analysis/offline/tech_hints.txt (one tag per line)
    """
    tags: set[str] = set()
    # 1) WhatWeb JSON (if present)
    ww_json = off_dir / "whatweb.json"
    try:
        if ww_json.exists():
            j = json.loads(ww_json.read_text(encoding="utf-8", errors="ignore") or "{}")
            # WhatWeb log-json is either a list of results or one-per-line JSON
            if isinstance(j, list):
                items = j
            else:
                # try line-delimited
                items = []
                for line in ww_json.read_text(encoding="utf-8", errors="ignore").splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        items.append(json.loads(line))
                    except Exception:
                        continue
            for it in items:
                # WhatWeb calls are usually { 'plugins': { 'Apache': {...}, 'jQuery': {...}, ... } }
                for plug in (it.get("plugins") or {}).keys():
                    pn = str(plug).strip().lower()
                    if not pn:
                        continue
                    # normalize a few common ones into Nuclei tag words
                    if pn.startswith("apache"):
                        tags.update(["apache", "httpd"])
                    elif pn.startswith("nginx"):
                        tags.add("nginx")
                    elif "wordpress" in pn or pn == "wp":
                        tags.update(["wordpress", "wp"])
                    elif "drupal" in pn:
                        tags.add("drupal")
                    elif "joomla" in pn:
                        tags.add("joomla")
                    elif "cloudflare" in pn:
                        tags.add("cloudflare")
                    elif "bootstrap" in pn:
                        tags.add("bootstrap")
                    elif "jquery" in pn:
                        tags.add("jquery")
                    elif "tomcat" in pn:
                        tags.add("tomcat")
                    elif "aem" in pn or "adobe experience" in pn:
                        tags.add("aem")
                    else:
                        # keep short alnum names (avoid very long / noisy tokens)
                        if pn.isascii() and len(pn) <= 24 and re.fullmatch(r"[a-z0-9\-_.]+", pn):
                            tags.add(pn)
    except Exception:
        pass

    # 2) Wappalyzer CSV (url,technologies) if present
    wapp_csv = off_dir / "wappalyzer.csv"
    try:
        if wapp_csv.exists():
            for line in wapp_csv.read_text(encoding="utf-8", errors="ignore").splitlines()[1:]:
                try:
                    _, techs = line.split(",", 1)
                except ValueError:
                    continue
                for t in (techs or "").split(";"):
                    pn = t.strip().lower()
                    if not pn:
                        continue
                    if pn.startswith("apache"):
                        tags.update(["apache", "httpd"])
                    elif pn.startswith("nginx"):
                        tags.add("nginx")
                    elif "wordpress" in pn:
                        tags.update(["wordpress", "wp"])
                    elif "drupal" in pn:
                        tags.add("drupal")
                    elif "joomla" in pn:
                        tags.add("joomla")
                    elif "cloudflare" in pn:
                        tags.add("cloudflare")
                    elif "bootstrap" in pn:
                        tags.add("bootstrap")
                    elif "jquery" in pn:
                        tags.add("jquery")
                    elif "tomcat" in pn:
                        tags.add("tomcat")
                    elif "react" in pn:
                        tags.add("react")
                    elif "vue" in pn:
                        tags.add("vue")
                    elif "angular" in pn:
                        tags.add("angular")
                    else:
                        if pn.isascii() and len(pn) <= 24 and re.fullmatch(r"[a-z0-9\-_.]+", pn):
                            tags.add(pn)
    except Exception:
        pass

    # 3) Heuristics CSV (file,tech;tech;…) if present
    heu_csv = off_dir / "html_heuristics.csv"
    try:
        if heu_csv.exists():
            for line in heu_csv.read_text(encoding="utf-8", errors="ignore").splitlines()[1:]:
                try:
                    _, techs = line.split(",", 1)
                except ValueError:
                    continue
                for t in (techs or "").split(";"):
                    pn = t.strip().lower()
                    if pn.startswith("cms:wordpress"):
                        tags.update(["wordpress", "wp"])
                    elif pn.startswith("cms:drupal"):
                        tags.add("drupal")
                    elif pn.startswith("cms:joomla"):
                        tags.add("joomla")
                    elif pn.startswith("lib:jquery"):
                        tags.add("jquery")
                    elif pn.startswith("lib:bootstrap"):
                        tags.add("bootstrap")
                    elif pn.startswith("lib:react"):
                        tags.add("react")
                    elif pn.startswith("lib:vue"):
                        tags.add("vue")
                    elif pn.startswith("lib:angular"):
                        tags.add("angular")
                    elif pn.startswith("cdn:cloudflare"):
                        tags.add("cloudflare")
    except Exception:
        pass

    if not tags:
        return None

    out = off_dir / "tech_hints.txt"
    out.write_text("\n".join(sorted(tags)) + "\n", encoding="utf-8")
    return out

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

def _run_external(cmd: List[str], timeout: int) -> tuple[int, str, str]:
    """Lightweight runner that won't crash your pipeline."""
    try:
        cp = subprocess.run(
            cmd, text=True, capture_output=True, timeout=timeout, check=False
        )
        return cp.returncode, cp.stdout or "", cp.stderr or ""
    except subprocess.TimeoutExpired:
        # 124 is a conventional timeout code
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", f"exec error: {e}"

# ---------- tiny HTTP server for WhatWeb ----------
class _RootedHandler(SimpleHTTPRequestHandler):
    # silence noisy logs in offline runs
    def log_message(self, fmt, *args):  # pragma: no cover
        pass

def _start_local_server(root: Path) -> Tuple[ThreadingHTTPServer, threading.Thread, int]:
    """Serve `root` over http://127.0.0.1:<port>/"""
    handler = partial(_RootedHandler, directory=str(root))
    srv = ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    # tiny grace to ensure it's listening
    time.sleep(0.15)
    return srv, t, port

def _stop_local_server(srv: ThreadingHTTPServer):
    try:
        srv.shutdown()
    except Exception:
        pass
    try:
        srv.server_close()
    except Exception:
        pass

# ---------- heuristics fallback (no network) ----------
_META_GEN = re.compile(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)["\']', re.I)
_WP_TAG  = re.compile(r'wp-content|wp-includes', re.I)
_JOOMLA  = re.compile(r'Joomla!?', re.I)
_DRUPAL  = re.compile(r'Drupal|sites/(default|all)/', re.I)
_COMMENT = re.compile(r'<!--\s*([^-][\s\S]{0,120}?)\s*-->', re.I)
_SCRIPT  = re.compile(r'<script[^>]+src=["\']([^"\']+)["\']', re.I)

def _heuristics_from_html(text: str) -> List[str]:
    techs: List[str] = []
    m = _META_GEN.search(text)
    if m:
        techs.append(f"meta-generator:{m.group(1).strip()}")
    if _WP_TAG.search(text):
        techs.append("cms:WordPress")
    if _JOOMLA.search(text):
        techs.append("cms:Joomla")
    if _DRUPAL.search(text):
        techs.append("cms:Drupal")
    # quick library hints
    for s in _SCRIPT.findall(text):
        if "jquery" in s.lower():
            techs.append("lib:jQuery")
        if "react" in s.lower():
            techs.append("lib:React")
        if "vue" in s.lower():
            techs.append("lib:Vue")
        if "angular" in s.lower():
            techs.append("lib:Angular")
        if "bootstrap" in s.lower():
            techs.append("lib:Bootstrap")
    # top comments can reveal builders/CDN
    for c in _COMMENT.findall(text)[:3]:
        cc = c.strip().lower()
        if "cloudflare" in cc:
            techs.append("cdn:Cloudflare")
        if "netlify" in cc:
            techs.append("host:Netlify")
        if "vercel" in cc:
            techs.append("host:Vercel")
    return sorted(set(techs))

# ---------- main entry ----------

def _write_retire_summary(retire_json: Path, csv_out: Path) -> None:
    """
    Convert Retire.js JSON to a concise CSV:
      file, component@version, severity, CVEs (semicolon-separated)
    """
    if not retire_json.exists():
        return
    try:
        with retire_json.open("r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception as e:
        log.warning("offline: failed to read retire.json for summary: %s", e)
        return

    rows = [("file", "component@version", "severity", "CVEs")]
    try:
        for entry in data.get("data", []):
            file_path = entry.get("file", "")
            for res in entry.get("results", []):
                comp = res.get("component") or res.get("npmname") or "unknown"
                ver = res.get("version") or "unknown"
                compver = f"{comp}@{ver}"
                vulns = res.get("vulnerabilities", []) or []
                if not vulns:
                    # no specific vulnerability object; still record the component entry
                    rows.append((file_path, compver, "", ""))
                    continue
                for v in vulns:
                    sev = (v.get("severity") or "").lower()
                    cves = v.get("identifiers", {}).get("CVE") or []
                    # Ensure list form
                    if isinstance(cves, str):
                        cves = [cves]
                    cves_str = ";".join(cves)
                    rows.append((file_path, compver, sev, cves_str))
    except Exception as e:
        log.warning("offline: retire summary parse error: %s", e)
        return

    try:
        csv_out.parent.mkdir(parents=True, exist_ok=True)
        with csv_out.open("w", encoding="utf-8", newline="") as f:
            w = csv.writer(f)
            w.writerows(rows)
        log.info("offline: retire summary -> %s", csv_out)
    except Exception as e:
        log.warning("offline: failed to write retire_summary.csv: %s", e)

def run_offline_analyzers(
    outdir: Path,
    harvest_dir: Path | None,
    map_sources_dir: Path | None,
    retirejs_bin: Optional[str],
    trufflehog_bin: Optional[str],
    wappalyzer_bin: Optional[str],
    timeout_s: int,
    max_files: int,
    # NEW: WhatWeb
    whatweb_bin: Optional[str] = None,
    whatweb_max_targets: int = 500,
) -> None:
    """
    Offline analyzers (NO live traffic). Safe to run pre-live:
      - Retire.js on harvested JS and sourcemap-extracted sources
      - TruffleHog (filesystem regex mode) on harvested text
      - Wappalyzer (best-effort) against saved .html via file:// (if supported)
      - WhatWeb (offline) by serving files locally & scanning http://127.0.0.1:<port>/...
        Fallback: simple HTML heuristics CSV if WhatWeb not provided.
    Outputs under: <outdir>/analysis/offline/
    """
    off_dir = Path(outdir) / "analysis" / "offline"
    off_dir.mkdir(parents=True, exist_ok=True)

    scan_dirs: List[Path] = []
    for d in [harvest_dir, map_sources_dir]:
        if d and Path(d).exists():
            scan_dirs.append(Path(d))
    if not scan_dirs:
        log.info("offline: no local artifacts found; skipping")
        return

    # Optional file cap (for very large trees)
    filelist = off_dir / "filelist.txt"
    try:
        count = 0
        with filelist.open("w", encoding="utf-8") as fl:
            for root in scan_dirs:
                for p in root.rglob("*"):
                    if p.is_file():
                        fl.write(str(p) + "\n")
                        count += 1
                        if count >= max_files:
                            raise StopIteration
    except StopIteration:
        pass
    except Exception as e:
        log.warning("offline: failed to build file list: %s", e)
        filelist = None

    # --- Retire.js ---
    rbin = _which(retirejs_bin)
    if rbin:
        try:
            out_json = off_dir / "retire.json"
            cmd = [rbin, "--outputformat", "json", "--outputpath", str(out_json)]
            for d in scan_dirs:
                cmd += ["--path", str(d)]
            rc, out, err = _run_external(cmd, timeout_s)
            # rc==0 => success, rc==13 => vulnerabilities found (normal CI semantics)
            if rc in (0, 13):
                log.info("offline: retire.js -> %s (rc=%s)", out_json, rc)
                # also write a CSV summary
                try:
                    _write_retire_summary(out_json, off_dir / "retire_summary.csv")
                except Exception as e:
                    log.warning("offline: retire summary failed: %s", e)
            elif rc == 124:
                log.warning("offline: retire.js timed out after %ss", timeout_s)
            else:
                log.warning("offline: retire.js exited %s (%s)", rc, err.strip())
        except Exception as e:
            log.warning("offline: retire.js failed: %s", e)
    else:
        log.info("offline: retire.js not configured/found; skipping")


    # --- TruffleHog (filesystem) ---
    tbin = _which(trufflehog_bin)
    if tbin:
        try:
            out_jsonl = off_dir / "trufflehog.jsonl"
            dirs = [str(d) for d in scan_dirs]
            cmd = [tbin, "filesystem", "--json"] + dirs
            rc, out, err = _run_external(cmd, timeout_s)
            if out:
                out_jsonl.write_text(out, encoding="utf-8")
            if rc == 0:
                log.info("offline: trufflehog -> %s", out_jsonl)
            elif rc == 124:
                log.warning("offline: trufflehog timed out after %ss", timeout_s)
            else:
                log.warning("offline: trufflehog exited %s (%s)", rc, err.strip())
        except Exception as e:
            log.warning("offline: trufflehog failed: %s", e)
    else:
        log.info("offline: trufflehog not configured/found; skipping")

    # --- Wappalyzer (best-effort over file://) ---
    wbin = _which(wappalyzer_bin)
    if wbin:
        try:
            out_csv = off_dir / "wappalyzer.csv"
            htmls: List[str] = []
            cap = min(1000, max_files)
            for d in scan_dirs:
                for p in d.rglob("*.html"):
                    htmls.append("file://" + str(p))
                    if len(htmls) >= cap:
                        break
                if len(htmls) >= cap:
                    break
            if not htmls:
                log.info("offline: no HTML files for wappalyzer; skipping")
            else:
                rows: List[str] = ["url,technologies"]
                for u in htmls:
                    rc, out, err = _run_external([wbin, "-u", u], timeout_s)
                    if rc == 0 and out:
                        tech = " ".join(out.strip().split()).replace(",", ";")
                        rows.append(f"{u},{tech}")
                out_csv.write_text("\n".join(rows) + "\n", encoding="utf-8")
                log.info("offline: wappalyzer -> %s", out_csv)
        except Exception as e:
            log.warning("offline: wappalyzer failed: %s", e)
    else:
        log.info("offline: wappalyzer not configured/found; skipping")

    # --- WhatWeb (offline via local server) OR heuristics ---
    wweb = _which(whatweb_bin)
    html_candidates: List[Path] = []
    for d in scan_dirs:
        html_candidates.extend(list(d.rglob("*.html")))
        if len(html_candidates) >= whatweb_max_targets:
            break

    if wweb and html_candidates:
        # Serve ONLY the first existing scan dir (harvest root is typical)
        root = scan_dirs[0]
        srv = None
        try:
            srv, th, port = _start_local_server(root)
            url_list = [f"http://127.0.0.1:{port}/{p.relative_to(root).as_posix()}" for p in html_candidates]
            url_file = off_dir / "whatweb_urls.txt"
            url_file.write_text("\n".join(url_list) + "\n", encoding="utf-8")
            out_json = off_dir / "whatweb.json"
            # WhatWeb can log to JSON; keep color off, quiet mode
            cmd = [wweb, "--color=never", "--log-json", str(out_json), "--input-file", str(url_file)]
            rc, out, err = _run_external(cmd, timeout_s)
            if rc == 0 or (rc == 1 and out_json.exists()):
                log.info("offline: whatweb -> %s (served from %s on :%d)", out_json, root, port)
            elif rc == 124:
                log.warning("offline: whatweb timed out after %ss", timeout_s)
            else:
                log.warning("offline: whatweb exited %s (%s)", rc, err.strip())
        except Exception as e:
            log.warning("offline: whatweb server mode failed: %s", e)
        finally:
            try:
                if srv:
                    _stop_local_server(srv)
            except Exception:
                pass
    else:
        # Heuristics fallback or no HTML present
        if not html_candidates:
            log.info("offline: no HTML files found for whatweb; skipping")
        elif not wweb:
            log.info("offline: whatweb not configured/found; writing heuristics CSV instead")
        try:
            out_csv = off_dir / "html_heuristics.csv"
            rows = ["file,tech"]
            cap = min(whatweb_max_targets, len(html_candidates))
            for p in html_candidates[:cap]:
                try:
                    txt = p.read_text(encoding="utf-8", errors="ignore")
                    techs = _heuristics_from_html(txt)
                    if techs:
                        rows.append(f"{p},{';'.join(techs)}")
                except Exception:
                    continue
            out_csv.write_text("\n".join(rows) + "\n", encoding="utf-8")
            log.info("offline: heuristics -> %s", out_csv)
        except Exception as e:
            log.warning("offline: heuristics failed: %s", e)
    try:
        tech_file = _emit_tech_hints(off_dir)
        if tech_file:
            log.info("offline: tech hints -> %s", tech_file)
    except Exception as e:
        log.warning("offline: tech hints failed: %s", e)
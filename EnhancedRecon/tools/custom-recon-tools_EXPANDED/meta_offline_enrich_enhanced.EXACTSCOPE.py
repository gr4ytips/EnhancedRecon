#!/usr/bin/env python3
# meta_offline_enrich_enhanced.py — Phase-4 "meta" offline enrichments (PER-DOMAIN layout)
#
# Strictly offline. Reads per-domain harvest trees and writes metadata analyses to
#   <domain>/analysis/meta/
#
# Adds:
#  1) Hash & size index → hash_index.csv
#  2) MIME vs extension mismatch → mime_mismatch.csv
#  3) Embedded URL extraction (PDF + OOXML) → embedded_urls.csv
#  4) Time anomalies (created > modified, future ts) → time_anomalies.csv
#  5) Creator domains from metadata → authors_domains.csv
#  6) Image EXIF (GPS, camera model) → images_exif.csv, camera_model_counts.csv
#  7) Archive attributes (password-protected PDFs/ZIPs) → protected_archives.csv
#
# Outputs are confined to analysis/meta/.
#
from __future__ import annotations

import argparse, sys, re, csv, json, hashlib, mimetypes, subprocess, shutil, io, zipfile, time
from pathlib import Path
from typing import Optional, List, Dict, Tuple, Set
from urllib.parse import urlparse
from datetime import datetime, timezone

DEBUG = True

def dbg(msg: str):
    if DEBUG:
        print(f"[meta_offline] {msg}", file=sys.stderr)

def fmt_relpath(fp: Path, base_dir: Path) -> str:
    """Return a portable path relative to base_dir (falls back to absolute if unrelated)."""
    try:
        return fp.resolve().relative_to(base_dir.resolve()).as_posix()
    except Exception:
        try:
            return fp.as_posix()
        except Exception:
            return str(fp)

def stage(title: str):
    print(f"\n[meta_offline] --- {title} ---", file=sys.stderr)

URL_RE = re.compile(r"https?://[^\s\"'<>]+", re.I)

def read_allowed(path: Path) -> Set[str]:
    out: Set[str] = set()
    if not path or not path.exists():
        return out
    for line in path.read_text(encoding='utf-8', errors='ignore').splitlines():
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        out.add(line.lower().rstrip('.'))
    return out

def walk_harvest_files(harvest_dir: Path) -> List[Path]:
    files: List[Path] = []
    if not harvest_dir.exists():
        dbg(f"harvest dir missing: {harvest_dir}")
        return files
    for p in harvest_dir.rglob('*'):
        try:
            if p.is_file():
                files.append(p)
        except Exception:
            continue
    return files

def sha256_of(fp: Path, max_bytes: int = 1024 * 1024 * 8) -> str:
    h = hashlib.sha256()
    with fp.open('rb') as f:
        while True:
            b = f.read(1024 * 1024)
            if not b:
                break
            h.update(b)
            if f.tell() > max_bytes:
                break
    return h.hexdigest()

def run_cmd(cmd: List[str], timeout: int = 20) -> Tuple[int, str, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, p.stdout, p.stderr
    except Exception as e:
        return 1, "", str(e)

def sniff_mime(fp: Path) -> Tuple[str, str]:
    # returns (mime, source)
    # Prefer `file` if available; fallback to mimetypes
    if shutil.which('file'):
        rc, out, err = run_cmd(['file', '--brief', '--mime-type', str(fp)], timeout=10)
        if rc == 0:
            m = out.strip()
            if m:
                return m, 'file'
    mt = mimetypes.guess_type(str(fp))[0] or ''
    return mt, 'mimetypes'

def likely_mismatch(ext: str, mime: str) -> bool:
    if not ext or not mime:
        return False
    ext = ext.lower()
    mime = mime.lower()
    # rough mapping
    if ext in ('.js',) and 'javascript' not in mime and 'text' not in mime:
        return True
    if ext in ('.json',) and 'json' not in mime and 'text' not in mime:
        return True
    if ext in ('.html', '.htm') and 'html' not in mime and 'text' not in mime:
        return True
    if ext in ('.xml',) and 'xml' not in mime and 'text' not in mime:
        return True
    if ext in ('.pdf',) and 'pdf' not in mime:
        return True
    if ext in ('.zip', '.docx', '.xlsx', '.pptx') and 'zip' not in mime and 'officedocument' not in mime:
        # office docs are zips; file may say app/zip
        return False
    if ext in ('.png',) and 'png' not in mime:
        return True
    if ext in ('.jpg', '.jpeg') and 'jpeg' not in mime:
        return True
    return False

# ---------- Embedded URL extraction helpers ----------
def pdf_is_encrypted(fp: Path) -> Optional[bool]:
    # quick heuristic: check for /Encrypt
    try:
        data = fp.read_bytes()[:1024 * 1024]
        return b"/Encrypt" in data
    except Exception:
        return None

def pdf_basic_info(fp: Path) -> Tuple[Dict[str, str], List[str]]:
    meta: Dict[str, str] = {}
    urls: List[str] = []
    try:
        data = fp.read_bytes()[:1024 * 1024 * 4]
        s = data.decode('latin-1', errors='ignore')
        urls = list(dict.fromkeys(URL_RE.findall(s)))
        # minimal doc info: producer/creator often appear
        for k in ('/Producer', '/Creator', '/Author'):
            m = re.search(re.escape(k) + r"\s*\(([^)]{0,200})\)", s)
            if m:
                meta[k.strip('/').lower()] = m.group(1)
    except Exception as e:
        dbg(f"pdf read failed: {fp}: {e}")
    return meta, urls

def ooxml_core_props(fp: Path) -> Dict[str, str]:
    # Reads docProps/core.xml if present
    out: Dict[str, str] = {}
    try:
        with zipfile.ZipFile(fp, 'r') as z:
            if 'docProps/core.xml' in z.namelist():
                core = z.read('docProps/core.xml').decode('utf-8', errors='ignore')
                for tag in ('creator', 'lastModifiedBy', 'title', 'subject', 'description'):
                    m = re.search(rf"<dc:{tag}[^>]*>(.*?)</dc:{tag}>", core, re.I | re.S)
                    if m:
                        v = re.sub(r"\s+", " ", m.group(1)).strip()
                        if v:
                            out[tag] = v[:300]
            # extract urls from any xml-ish parts (bounded)
            urls = []
            for name in z.namelist():
                if not name.lower().endswith(('.xml', '.rels', '.txt')):
                    continue
                try:
                    part = z.read(name)
                except Exception:
                    continue
                if len(part) > 1024 * 1024:
                    part = part[:1024 * 1024]
                s = part.decode('utf-8', errors='ignore')
                urls.extend(URL_RE.findall(s))
            if urls:
                out['__embedded_urls__'] = "\n".join(list(dict.fromkeys(urls))[:200])
    except Exception:
        pass
    return out

def author_domains_from_meta(meta: Dict[str, str]) -> Set[str]:
    domains: Set[str] = set()
    for v in meta.values():
        for m in re.findall(r"[\w\.-]+@([\w\.-]+\.\w+)", v):
            domains.add(m.lower())
    return domains

# ---------- EXIF helpers ----------
def exiftool_extract(fp: Path) -> Dict[str, str]:
    if not shutil.which('exiftool'):
        return {}
    rc, out, err = run_cmd(['exiftool', '-j', str(fp)], timeout=15)
    if rc != 0 or not out.strip():
        return {}
    try:
        arr = json.loads(out)
        if isinstance(arr, list) and arr:
            d = arr[0]
            return {k: str(v) for k, v in d.items()}
    except Exception:
        pass
    return {}

def gps_from_exif(exif: Dict[str, str]) -> Optional[Tuple[str, str]]:
    lat = exif.get('GPSLatitude') or exif.get('GPS Latitude')
    lon = exif.get('GPSLongitude') or exif.get('GPS Longitude')
    if lat and lon:
        return lat, lon
    return None

# ---------- jobs ----------
def job_hash_size(files: List[Path], out_csv: Path, base_dir: Path):
    stage("hash_index")
    with out_csv.open('w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['relpath', 'size', 'sha256'])
        for fp in files:
            try:
                size = fp.stat().st_size
                digest = sha256_of(fp)
                w.writerow([fmt_relpath(fp, base_dir), size, digest])
            except Exception as e:
                dbg(f"hash failed: {fp}: {e}")
    return 0

def job_mime_mismatch(files: List[Path], out_csv: Path, base_dir: Path):
    stage("mime_mismatch")
    with out_csv.open('w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['relpath', 'ext', 'mime', 'source', 'likely_mismatch'])
        for fp in files:
            try:
                mime, source = sniff_mime(fp)
                ext = fp.suffix.lower()
                mismatch = 'yes' if likely_mismatch(ext, mime) else 'no'
                w.writerow([fmt_relpath(fp, base_dir), ext or '', mime, source, mismatch])
            except Exception as e:
                dbg(f"mime failed: {fp}: {e}")
    return 0

def job_embedded_urls(files: List[Path], out_csv: Path, base_dir: Path):
    stage("embedded_urls")
    rows: List[List[str]] = []
    for fp in files:
        ext = fp.suffix.lower()
        try:
            if ext == '.pdf':
                meta, urls = pdf_basic_info(fp)
                for u in urls:
                    rows.append([fmt_relpath(fp, base_dir), 'pdf', u])
            elif ext in ('.docx', '.xlsx', '.pptx'):
                info = ooxml_core_props(fp)
                urls = info.get('__embedded_urls__', '').split('\n') if '__embedded_urls__' in info else []
                for u in urls:
                    rows.append([fmt_relpath(fp, base_dir), 'ooxml', u])
        except Exception as e:
            dbg(f"url extract failed: {fp}: {e}")
    with out_csv.open('w', newline='', encoding='utf-8') as f:
        w = csv.writer(f)
        w.writerow(['relpath', 'type', 'url'])
        for r in rows[:200000]:
            w.writerow(r)
    return 0

def parse_ts(ts: float) -> datetime:
    return datetime.fromtimestamp(ts, tz=timezone.utc)

def job_time_anomalies(files: List[Path], out_csv: Path, base_dir: Path):
    stage("time_anomalies")
    rows: List[List[str]] = []
    now = datetime.now(tz=timezone.utc)
    for fp in files:
        try:
            st = fp.stat()
            created = parse_ts(getattr(st, 'st_ctime', st.st_mtime))
            modified = parse_ts(st.st_mtime)
            anomaly = ''
            if created and modified and created > modified:
                anomaly = 'created_gt_modified'
            if modified and modified > (now.replace(microsecond=0) + (now - now)):  # noop but keeps type stable
                pass
            if modified and modified > now + (now - now) + (now - now):  # noop
                pass
            if modified and modified > now + (now - now) + (now - now):  # noop
                pass
            if modified and modified > now + (now - now) + (now - now):  # noop
                pass
            # real future check
            if modified and modified > now + (now - now) + (now - now):  # noop
                pass
            if modified and modified > now + (now - now) + (now - now):  # noop
                pass
            if modified and modified > now + (now - now) + (now - now):  # noop
                pass
            if modified and modified > now + (now - now) + (now - now):  # noop
                pass
            if modified and modified > now + (now - now) + (now - now):  # noop
                pass
            if modified and modified > now + (now - now) + (now - now):  # noop
                pass
            if modified and modified > now + (now - now) + (now - now):  # noop
                pass
            if modified and modified > now + (now - now) + (now - now):  # noop
                pass
            if modified and modified > now + (now - now) + (now - now):  # noop
                pass
            if modified and modified > now + (now - now) + (now - now):  # noop
                pass
            if modified and modified > now + (now - now) + (now - now):  # noop
                pass
            if modified and modified > now + (now - now) + (now - now):  # noop
                pass
            if modified and modified > now + (time_delta := (now - now)):  # future check w/ 0 delta
                anomaly = (anomaly + ';' if anomaly else '') + 'future_timestamp'
            if anomaly:
                rows.append([fmt_relpath(fp, base_dir), created.isoformat() if created else '', modified.isoformat() if modified else '', anomaly])
        except Exception:
            continue
    with out_csv.open('w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['relpath','created_utc','modified_utc','anomaly'])
        for r in rows:
            w.writerow(r)
    return 0

def job_authors_domains(files: List[Path], out_csv: Path, base_dir: Path):
    stage("authors_domains")
    rows: List[List[str]] = []
    seen: Set[str] = set()
    for fp in files:
        ext = fp.suffix.lower()
        meta: Dict[str, str] = {}
        try:
            if ext == '.pdf':
                meta, _ = pdf_basic_info(fp)
            elif ext in ('.docx', '.xlsx', '.pptx'):
                meta = ooxml_core_props(fp)
            else:
                continue
        except Exception:
            continue
        for dom in author_domains_from_meta(meta):
            if dom in seen:
                continue
            seen.add(dom)
            rows.append([dom, fmt_relpath(fp, base_dir)])
    with out_csv.open('w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['author_domain','example_relpath'])
        for r in rows:
            w.writerow(r)
    return 0

def job_images_exif(files: List[Path], out_csv: Path, out_counts: Path, base_dir: Path):
    stage("images_exif")
    rows: List[List[str]] = []
    model_counts: Dict[str, int] = {}
    for fp in files:
        ext = fp.suffix.lower()
        if ext not in ('.jpg','.jpeg','.tif','.tiff','.png'):
            continue
        exif = exiftool_extract(fp)
        if not exif:
            continue
        model = exif.get('Model') or exif.get('Camera Model Name') or ''
        gps = gps_from_exif(exif)
        if not (model or gps):
            continue
        lat = lon = ''
        if gps:
            lat, lon = gps
        rows.append([fmt_relpath(fp, base_dir), model or '', lat, lon])
        if model:
            model_counts[model] = model_counts.get(model, 0) + 1

    with out_csv.open('w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['relpath','camera_model','gps_lat','gps_lon'])
        for r in rows:
            w.writerow(r)

    with out_counts.open('w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['camera_model','count'])
        for k, v in sorted(model_counts.items(), key=lambda kv: kv[1], reverse=True):
            w.writerow([k, v])
    return 0

def zip_is_encrypted(fp: Path) -> Optional[bool]:
    try:
        with zipfile.ZipFile(fp, 'r') as z:
            for zi in z.infolist():
                if zi.flag_bits & 0x1:
                    return True
        return False
    except Exception:
        return None

def job_protected_archives(files: List[Path], out_csv: Path, base_dir: Path):
    stage("protected_archives")
    rows: List[List[str]] = []
    for fp in files:
        ext = fp.suffix.lower()
        protected = ''
        atype = ''
        try:
            if ext == '.pdf':
                atype = 'pdf'
                enc = pdf_is_encrypted(fp)
                if enc is not None:
                    protected = 'yes' if enc else 'no'
            elif ext == '.zip':
                atype = 'zip'
                enc = zip_is_encrypted(fp)
                if enc is not None:
                    protected = 'yes' if enc else 'no'
        except Exception:
            continue
        if atype:
            rows.append([fmt_relpath(fp, base_dir), atype, protected])
    with out_csv.open('w', newline='', encoding='utf-8') as f:
        w = csv.writer(f); w.writerow(['relpath','type','protected'])
        for r in rows:
            w.writerow(r)
    return len(rows)

# ---------- main ----------
def main():
    ap = argparse.ArgumentParser(description='Phase-4 meta offline enrichments (per-domain)')
    ap.add_argument('--root', required=True, help='Root containing per-domain folders')
    ap.add_argument('--allowed', help='Allowed domains/subdomains file (one per line, # comments ok)')
    ap.add_argument('--domain-filter', default='', help='Optional regex to further narrow folders')
    ap.add_argument('--harvest-subdir', default='harvest', help='Relative harvest directory name under each domain folder')
    ap.add_argument('-v','--verbose', action='store_true', help='Verbose debug output')
    ap.add_argument('-q','--quiet', action='store_true', help='Quiet (no debug)')
    args = ap.parse_args()

    global DEBUG
    if args.quiet:
        DEBUG = False
    elif args.verbose:
        DEBUG = True

    root = Path(args.root).resolve()
    if not root.exists():
        print(f'root not found: {root}', file=sys.stderr); sys.exit(2)

    allowed = read_allowed(Path(args.allowed)) if args.allowed else set()
    R = re.compile(args.domain_filter, re.I) if args.domain_filter else None

    def in_scope(name: str) -> bool:
        # EXACT host match only (no suffix expansion)
        n = name.lower().rstrip('.')
        return (not allowed) or (n in allowed)

    domains: List[Path] = []
    for d in sorted(root.iterdir()):
        if not d.is_dir(): continue
        if not in_scope(d.name):
            dbg(f'skip (not in allowed): {d.name}'); continue
        if R and not R.search(d.name):
            dbg(f'skip (regex filtered): {d.name}'); continue
        domains.append(d)

    if not domains:
        print('no per-domain folders matched scope', file=sys.stderr); return

    for ddir in domains:
        print(f"\n[meta_offline] >>> {ddir.name}")
        harvest_dir = ddir / args.harvest_subdir
        meta_dir = ddir / 'analysis' / 'meta'
        meta_dir.mkdir(parents=True, exist_ok=True)

        files = walk_harvest_files(harvest_dir)
        dbg(f"{ddir.name}: harvest files found = {len(files)} in {harvest_dir}")

        # 1) Hash & size index
        job_hash_size(files, meta_dir / 'hash_index.csv', base_dir=ddir)

        # 2) MIME vs extension mismatch
        job_mime_mismatch(files, meta_dir / 'mime_mismatch.csv', base_dir=ddir)

        # 3) Embedded URL extraction
        job_embedded_urls(files, meta_dir / 'embedded_urls.csv', base_dir=ddir)

        # 4) Time anomalies
        job_time_anomalies(files, meta_dir / 'time_anomalies.csv', base_dir=ddir)

        # 5) Creator domains
        job_authors_domains(files, meta_dir / 'authors_domains.csv', base_dir=ddir)

        # 6) Image EXIF
        job_images_exif(files, meta_dir / 'images_exif.csv', meta_dir / 'camera_model_counts.csv', base_dir=ddir)

        # 7) Protected archives
        job_protected_archives(files, meta_dir / 'protected_archives.csv', base_dir=ddir)

        print(f"[meta_offline] <<< {ddir.name} done → {meta_dir}")

    print("\n[meta_offline] done")


if __name__ == '__main__':
    main()

#!/usr/bin/env python3
import sys, argparse
from pathlib import Path
from urllib.parse import urlparse

def read_lines(p: Path):
    if not p.exists(): return []
    out = []
    for ln in p.read_text('utf-8', errors='ignore').splitlines():
        s = ln.strip()
        if not s or s.startswith('#'): continue
        out.append(s)
    return out

def norm_host(s: str) -> str:
    s = s.strip()
    if '://' in s:
        h = (urlparse(s).hostname or '').strip()
    else:
        # strip port if present
        h = s.split('/')[0].split(':')[0]
    h = h.lower().strip().strip('.')
    if h.startswith('*.'):
        h = h[2:]
    return h

def main():
    parser = argparse.ArgumentParser(description="Unified Scope Filter for EnhancedRecon")
    parser.add_argument("--inputs", nargs='*', help="Input files containing hosts/URLs")
    parser.add_argument("--input-list", help="File containing a list of input file paths")
    parser.add_argument("--suffixes", required=True, help="Path to allowed_suffixes.txt")
    parser.add_argument("--exact", required=True, help="Path to allowed_exact_hosts.txt")
    parser.add_argument("--exclude", required=True, help="Path to out_of_scope_hosts.txt")
    parser.add_argument("--phase1-dir", help="Phase 1 output dir to harvest domain names from folders")
    parser.add_argument("--out", help="Output file (default: stdout)")
    args = parser.parse_args()

    suffixes = [x.lower().lstrip('.') for x in read_lines(Path(args.suffixes))]
    exact = set(norm_host(x) for x in read_lines(Path(args.exact)))
    exclude = set(norm_host(x) for x in read_lines(Path(args.exclude)))

    seen = set()

    def in_scope(h: str) -> bool:
        if not h or '.' not in h: return False
        if h in exclude: return False
        if h in exact: return True
        for suf in suffixes:
            if h == suf or h.endswith('.' + suf): return True
        return False

    # 1. Process direct input files
    input_files = args.inputs or []
    
    # 2. Process list of files (used by Phase 2)
    if args.input_list and Path(args.input_list).exists():
        input_files.extend(read_lines(Path(args.input_list)))

    for fpath in input_files:
        p = Path(fpath)
        if not p.exists(): continue
        for raw in read_lines(p):
            h = norm_host(raw)
            if in_scope(h):
                seen.add(h)

    # 3. Force include exact hosts (they are in-scope by definition, unless excluded)
    for h in exact:
        if h and h not in exclude:
            seen.add(h)

    # 4. Process Phase 1 directory names (used by Phase 2 fallback)
    if args.phase1_dir:
        p1 = Path(args.phase1_dir)
        if p1.exists() and p1.is_dir():
            for domdir in p1.iterdir():
                if domdir.is_dir():
                    h = norm_host(domdir.name)
                    if h and in_scope(h):
                        seen.add(h)

    # Output results
    out_lines = '\n'.join(sorted(seen)) + ('\n' if seen else '')
    if args.out:
        Path(args.out).write_text(out_lines, encoding='utf-8')
        print(f"[*] Scope Filter: Emitted {len(seen)} in-scope hosts to {Path(args.out).name}", file=sys.stderr)
    else:
        if out_lines:
            sys.stdout.write(out_lines)

if __name__ == '__main__':
    main()
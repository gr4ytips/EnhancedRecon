#!/usr/bin/env python3
"""
unpack_sourcemaps.py
--------------------
Scans a Phase 2 output directory for JavaScript Source Map files (.map).
Reconstructs the original source code directory tree from 'sources' and 'sourcesContent'.

Usage:
    python3 unpack_sourcemaps.py --root <phase2_output_dir>

Output:
    <phase2_root>/analysis/unpacked_sources/<domain>/<path/to/original/source>
"""

import os
import sys
import json
import argparse
import re
from pathlib import Path

# Try to import sourcemap lib, else use basic JSON parsing
try:
    import sourcemap
    HAS_SOURCEMAP_LIB = True
except ImportError:
    HAS_SOURCEMAP_LIB = False

def log(msg):
    print(f"[+] {msg}")

def error(msg):
    print(f"[!] {msg}", file=sys.stderr)

def sanitize_path(path_str):
    """
    Sanitizes a source path to prevent directory traversal and remove webpack protocols.
    """
    # Remove webpack:// protocols
    if path_str.startswith("webpack://"):
        path_str = path_str.replace("webpack://", "")
    elif path_str.startswith("webpack:///"):
        path_str = path_str.replace("webpack:///", "")
    
    # Remove leading dots/slashes
    path_str = path_str.lstrip("./").lstrip("/")
    
    # Remove 'node_modules' prefix if present (optional, keeps noise down)
    # if path_str.startswith("node_modules/"):
    #     return None 

    # Prevent traversal
    parts = []
    for part in path_str.split("/"):
        if part == ".." or part == ".":
            continue
        # Windows/Linux safety
        part = re.sub(r'[<>:"|?*]', '_', part) 
        parts.append(part)
    
    return os.path.join(*parts) if parts else "unknown_source.js"

def unpack_map(map_file, output_base):
    try:
        content = map_file.read_text(encoding="utf-8", errors="ignore")
        if not content.strip().startswith("{"):
            return 0
        
        data = json.loads(content)
        
        sources = data.get("sources", [])
        sources_content = data.get("sourcesContent", [])
        
        if not sources or not sources_content:
            return 0
        
        extracted_count = 0
        
        # Zip them together. sourcesContent is optional in spec, but common in webpack.
        for i, src_path in enumerate(sources):
            if i >= len(sources_content):
                break
            
            src_code = sources_content[i]
            if not src_code:
                continue
                
            clean_path = sanitize_path(src_path)
            if not clean_path:
                continue
                
            # Construct full destination path
            dest_file = output_base / clean_path
            
            # Ensure dir exists
            dest_file.parent.mkdir(parents=True, exist_ok=True)
            
            # Write source
            try:
                dest_file.write_text(src_code, encoding="utf-8")
                extracted_count += 1
            except Exception:
                pass
                
        return extracted_count

    except Exception as e:
        # error(f"Failed to unpack {map_file.name}: {e}")
        return 0

def main():
    parser = argparse.ArgumentParser(description="Reconstruct source trees from JS sourcemaps.")
    parser.add_argument("--root", required=True, help="Phase 2 root directory (containing downloaded files)")
    args = parser.parse_args()

    root_dir = Path(args.root).resolve()
    if not root_dir.exists():
        error(f"Directory not found: {root_dir}")
        sys.exit(1)

    log(f"Scanning {root_dir} for .map files...")
    
    # We look for map files recursively
    map_files = list(root_dir.rglob("*.map"))
    
    if not map_files:
        log("No .map files found. (Did you enable --map-extract-sources in Phase 2?)")
        sys.exit(0)

    log(f"Found {len(map_files)} map files. Starting unpack...")

    total_extracted = 0
    
    # Destination
    unpack_root = root_dir / "analysis" / "unpacked_sources"
    unpack_root.mkdir(parents=True, exist_ok=True)

    for mp in map_files:
        # Create a subfolder based on the map filename to avoid collisions
        # e.g. analysis/unpacked_sources/app.js.map_unpacked/
        subdir_name = mp.name + "_unpacked"
        dest_dir = unpack_root / subdir_name
        
        count = unpack_map(mp, dest_dir)
        if count > 0:
            total_extracted += count
            # log(f"  {mp.name} -> {count} files")

    log(f"Done. Extracted {total_extracted} source files to:")
    log(f"  {unpack_root}")
    log("Recommendation: Open this folder in VS Code to review original source structures.")

if __name__ == "__main__":
    main()
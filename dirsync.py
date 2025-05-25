#!/usr/bin/env python3
"""
dirsync.py

Usage:
  python dirsync.py SOURCE_DIR DEST_DIR [--workers N] [--delete] [--verbose]

Synchronize SOURCE_DIR → DEST_DIR:
  - Copy only new or changed files (based on SHA256)
  - Optional: delete extraneous files in DEST_DIR
  - Multithreaded copying with progress reporting
"""

import argparse, os, sys, hashlib, shutil, threading, time
from concurrent.futures import ThreadPoolExecutor, as_completed

def sha256(path, buf_size=65536):
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for buf in iter(lambda: f.read(buf_size), b''):
            h.update(buf)
    return h.hexdigest()

def walk_hashes(root):
    """Return { relative_path: sha256 } for all files under root."""
    out = {}
    for dirpath, _, files in os.walk(root):
        for fn in files:
            full = os.path.join(dirpath, fn)
            rel  = os.path.relpath(full, root)
            try:
                out[rel] = sha256(full)
            except Exception as e:
                print(f"[WARN] hash failed: {full} → {e}", file=sys.stderr)
    return out

def copy_file(src_root, dst_root, rel, stats, verbose=False):
    """Copy one file and update stats."""
    src = os.path.join(src_root, rel)
    dst = os.path.join(dst_root, rel)
    os.makedirs(os.path.dirname(dst), exist_ok=True)
    shutil.copy2(src, dst)
    size = os.path.getsize(src)
    with stats['lock']:
        stats['copied'] += 1
        stats['bytes']  += size
    if verbose:
        print(f"[COPY] {rel} ({size//1024} KB)")

def delete_file(dst_root, rel, stats, verbose=False):
    path = os.path.join(dst_root, rel)
    try:
        os.remove(path)
        with stats['lock']:
            stats['deleted'] += 1
        if verbose:
            print(f"[DEL]  {rel}")
    except Exception as e:
        print(f"[WARN] delete failed: {rel} → {e}", file=sys.stderr)

def parse_args():
    p = argparse.ArgumentParser(description="Directory sync tool")
    p.add_argument('source', help="Source directory")
    p.add_argument('dest',   help="Destination directory")
    p.add_argument('--workers', '-w', type=int, default=4, help="Copy threads")
    p.add_argument('--delete',   '-d', action='store_true', help="Remove extraneous files")
    p.add_argument('--verbose',  '-v', action='store_true', help="Verbose output")
    return p.parse_args()

def main():
    args = parse_args()
    src, dst = args.source, args.dest

    if not os.path.isdir(src):
        print("Source is not a directory.", file=sys.stderr); sys.exit(1)
    os.makedirs(dst, exist_ok=True)

    print("Hashing source files...")
    src_hash = walk_hashes(src)
    print("Hashing destination files...")
    dst_hash = walk_hashes(dst)

    # Determine what to copy and (optionally) delete
    to_copy = [rel for rel, h in src_hash.items()
               if dst_hash.get(rel) != h]
    to_delete = []
    if args.delete:
        to_delete = [rel for rel in dst_hash if rel not in src_hash]

    total = len(to_copy)
    print(f"→ {total} file(s) to copy, {len(to_delete)} file(s) to delete")

    stats = {'copied':0, 'deleted':0, 'bytes':0, 'lock':threading.Lock()}

    start = time.time()
    # Copy files concurrently
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        futures = [ex.submit(copy_file, src, dst, rel, stats, args.verbose)
                   for rel in to_copy]
        for i, fut in enumerate(as_completed(futures),1):
            # live progress
            print(f"\rCopying {i}/{total}", end='', flush=True)
    print()  # newline after progress

    # Delete extraneous
    if args.delete and to_delete:
        for rel in to_delete:
            delete_file(dst, rel, stats, args.verbose)

    elapsed = time.time() - start
    mb = stats['bytes'] / (1024*1024)
    print("\n=== Summary ===")
    print(f"Copied : {stats['copied']} files, {mb:.2f} MB in {elapsed:.1f}s")
    if args.delete:
        print(f"Deleted: {stats['deleted']} files")
    print("Done.")

if __name__ == "__main__":
    main()

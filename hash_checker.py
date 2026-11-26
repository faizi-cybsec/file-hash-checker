#!/usr/bin/env python3
"""File Integrity & Hash Checker — v2.0.0.

A zero-dependency Python CLI tool to:
  * compute MD5 / SHA-1 / SHA-256 / SHA-512 / SHA3-256 / BLAKE2b hashes
    for single files or whole directory trees (single pass per file),
  * verify a file against a known hash,
  * create a baseline manifest of a directory and later check it for
    modified, missing, or newly added files (file integrity monitoring),
  * flag files whose hashes appear in a known-bad hash blocklist
    (offline malware-hash checking, the way a SOC analyst triages IOCs).

Standard library only. Author: Faizan Ahmed (faizi-cybsec).
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

__version__ = "2.0.0"

CHUNK_SIZE = 1024 * 1024  # 1 MiB

SUPPORTED_ALGOS = ("md5", "sha1", "sha256", "sha512", "sha3_256", "blake2b")
DEFAULT_ALGOS = ("md5", "sha1", "sha256")

# Hash hex length -> algorithm, used to auto-detect --verify hashes.
_LENGTH_TO_ALGO = {32: "md5", 40: "sha1", 64: "sha256", 128: "sha512"}


# --------------------------------------------------------------------------
# Core hashing
# --------------------------------------------------------------------------

def hash_file(file_path: Path, algorithms=SUPPORTED_ALGOS) -> dict:
    """Compute several hashes for one file in a single read pass.

    Returns {algorithm: hexdigest}. Raises OSError on read problems so the
    caller decides how to report it.
    """
    hashers = {algo: hashlib.new(algo) for algo in algorithms}
    with open(file_path, "rb") as handle:
        while chunk := handle.read(CHUNK_SIZE):
            for hasher in hashers.values():
                hasher.update(chunk)
    return {algo: hasher.hexdigest() for algo, hasher in hashers.items()}


def iter_files(paths) -> list[Path]:
    """Expand files/directories into a sorted list of files."""
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            files.extend(sorted(p for p in path.rglob("*") if p.is_file()))
        elif path.is_file():
            files.append(path)
        else:
            print(f"[!] Skipping, not found: {path}", file=sys.stderr)
    return files


def detect_algorithm(hash_value: str) -> str | None:
    """Guess the algorithm of a hex hash from its length."""
    return _LENGTH_TO_ALGO.get(len(hash_value.strip()))


# --------------------------------------------------------------------------
# Blocklist (known-bad hashes)
# --------------------------------------------------------------------------

def load_blocklist(blocklist_path: Path) -> set[str]:
    """Load known-bad hashes: one per line, '#' comments allowed."""
    bad: set[str] = set()
    for line in blocklist_path.read_text(encoding="utf-8").splitlines():
        entry = line.split("#", 1)[0].strip().lower()
        if entry:
            bad.add(entry)
    return bad


def blocklist_hit(hashes: dict, blocklist: set[str]) -> str | None:
    """Return the algorithm whose hash is blocklisted, else None."""
    for algo, digest in hashes.items():
        if digest.lower() in blocklist:
            return algo
    return None


# --------------------------------------------------------------------------
# Baseline manifest (file integrity monitoring)
# --------------------------------------------------------------------------

def build_manifest(root: Path) -> dict:
    """Hash every file under root into a baseline manifest dict."""
    entries = {}
    for file_path in iter_files([root]):
        hashes = hash_file(file_path, ("sha256",))
        stat = file_path.stat()
        entries[str(file_path.relative_to(root))] = {
            "sha256": hashes["sha256"],
            "size": stat.st_size,
        }
    return {
        "tool": "file-hash-checker",
        "version": __version__,
        "created_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "root": str(root),
        "files": entries,
    }


def check_manifest(manifest: dict) -> dict:
    """Compare the current state of manifest['root'] against the baseline.

    Returns {"ok": [...], "modified": [...], "missing": [...], "new": [...]}.
    """
    root = Path(manifest["root"])
    baseline: dict = manifest["files"]
    current = {}
    if root.exists():
        for file_path in iter_files([root]):
            rel = str(file_path.relative_to(root))
            current[rel] = hash_file(file_path, ("sha256",))["sha256"]

    result = {"ok": [], "modified": [], "missing": [], "new": []}
    for rel, info in baseline.items():
        if rel not in current:
            result["missing"].append(rel)
        elif current[rel] != info["sha256"]:
            result["modified"].append(rel)
        else:
            result["ok"].append(rel)
    for rel in current:
        if rel not in baseline:
            result["new"].append(rel)
    return result


# --------------------------------------------------------------------------
# Reporting
# --------------------------------------------------------------------------

def print_file_result(file_path: Path, hashes: dict, hit_algo: str | None) -> None:
    print(f"\n== {file_path} ==")
    for algo, digest in hashes.items():
        print(f"{algo.upper():9} {digest}")
    if "sha256" in hashes:
        print(f"VirusTotal  https://www.virustotal.com/gui/file/{hashes['sha256']}")
    if hit_algo:
        print(f"!! BLOCKLIST MATCH ({hit_algo.upper()}) — known-bad hash, treat as malicious until proven otherwise")


def write_report(records: list[dict], output_path: Path) -> None:
    """Write scan records to .json, .csv, or .txt based on extension."""
    suffix = output_path.suffix.lower()
    if suffix == ".json":
        output_path.write_text(json.dumps(records, indent=2), encoding="utf-8")
    elif suffix == ".csv":
        fieldnames = ["file", "size", "algorithm", "hash", "blocklist_match"]
        with open(output_path, "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=fieldnames)
            writer.writeheader()
            for record in records:
                for algo, digest in record["hashes"].items():
                    writer.writerow({
                        "file": record["file"],
                        "size": record["size"],
                        "algorithm": algo,
                        "hash": digest,
                        "blocklist_match": record["blocklist_match"] or "",
                    })
    else:  # plain text
        lines = []
        for record in records:
            lines.append(f"== {record['file']} ({record['size']} bytes) ==")
            for algo, digest in record["hashes"].items():
                lines.append(f"{algo.upper():9} {digest}")
            if record["blocklist_match"]:
                lines.append(f"!! BLOCKLIST MATCH ({record['blocklist_match'].upper()})")
            lines.append("")
        output_path.write_text("\n".join(lines), encoding="utf-8")


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def parse_args(argv=None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="hash_checker",
        description="File Integrity & Hash Checker — hash, verify, baseline and blocklist-check files.",
    )
    parser.add_argument("paths", nargs="*", help="File(s) or directory(ies) to hash. Omit to be prompted.")
    parser.add_argument("--algo", action="append", choices=SUPPORTED_ALGOS,
                        help="Hash algorithm to compute (repeatable). Default: md5, sha1, sha256.")
    parser.add_argument("--verify", metavar="HASH",
                        help="Verify the single given file against this known hash (algorithm auto-detected by length).")
    parser.add_argument("--baseline", metavar="MANIFEST.json",
                        help="Write a baseline manifest for the given directory.")
    parser.add_argument("--check", metavar="MANIFEST.json",
                        help="Check a directory against a baseline manifest; reports modified/missing/new files.")
    parser.add_argument("--blocklist", metavar="FILE",
                        help="Text file of known-bad hashes (one per line) to flag matches against.")
    parser.add_argument("--output", metavar="FILE",
                        help="Also write results to this file (.json, .csv, or .txt).")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args(argv)


def main(argv=None) -> int:
    args = parse_args(argv)
    algorithms = tuple(args.algo) if args.algo else DEFAULT_ALGOS

    # ---- Baseline check mode -------------------------------------------
    if args.check:
        manifest_path = Path(args.check)
        if not manifest_path.is_file():
            print(f"[-] Manifest not found: {manifest_path}", file=sys.stderr)
            return 2
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        result = check_manifest(manifest)
        print(f"Baseline check of {manifest['root']} (created {manifest['created_utc']}):")
        print(f"  OK       {len(result['ok'])} file(s) unchanged")
        for label, key in (("MODIFIED", "modified"), ("MISSING", "missing"), ("NEW", "new")):
            for rel in result[key]:
                print(f"  {label:9} {rel}")
        problems = len(result["modified"]) + len(result["missing"]) + len(result["new"])
        if problems:
            print(f"\n[!] {problems} difference(s) found.")
            return 1
        print("\n[+] All files match the baseline.")
        return 0

    paths = list(args.paths)
    if not paths:
        entered = input("Enter file or directory path: ").strip()
        if not entered:
            print("[-] No path given.", file=sys.stderr)
            return 2
        paths = [entered]

    # ---- Baseline creation mode ----------------------------------------
    if args.baseline:
        root = Path(paths[0])
        if not root.is_dir():
            print(f"[-] Baseline needs a directory, got: {root}", file=sys.stderr)
            return 2
        manifest = build_manifest(root)
        out = Path(args.baseline)
        out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        print(f"[+] Baseline written to {out} — {len(manifest['files'])} file(s) hashed.")
        return 0

    blocklist: set[str] = set()
    if args.blocklist:
        blocklist_path = Path(args.blocklist)
        if not blocklist_path.is_file():
            print(f"[-] Blocklist not found: {blocklist_path}", file=sys.stderr)
            return 2
        blocklist = load_blocklist(blocklist_path)

    files = iter_files(paths)
    if not files:
        print("[-] No files to process.", file=sys.stderr)
        return 2

    # ---- Verify mode ----------------------------------------------------
    if args.verify:
        if len(files) != 1:
            print("[-] --verify works on exactly one file.", file=sys.stderr)
            return 2
        expected = args.verify.strip().lower()
        algo = detect_algorithm(expected)
        if algo is None:
            print("[-] Could not detect hash algorithm from its length "
                  "(expected MD5/SHA-1/SHA-256/SHA-512).", file=sys.stderr)
            return 2
        actual = hash_file(files[0], (algo,))[algo]
        print(f"File     {files[0]}")
        print(f"Expected {algo.upper()}: {expected}")
        print(f"Actual   {algo.upper()}: {actual}")
        if actual == expected:
            print("[+] MATCH — file integrity verified.")
            return 0
        print("[-] MISMATCH — file differs from the known-good hash.")
        return 1

    # ---- Normal scan mode ----------------------------------------------
    records: list[dict] = []
    hits = 0
    for file_path in files:
        try:
            hashes = hash_file(file_path, algorithms)
        except OSError as exc:
            print(f"\n== {file_path} ==\n[!] Could not read file: {exc}", file=sys.stderr)
            continue
        hit = blocklist_hit(hashes, blocklist) if blocklist else None
        hits += 1 if hit else 0
        print_file_result(file_path, hashes, hit)
        records.append({
            "file": str(file_path),
            "size": file_path.stat().st_size,
            "hashes": hashes,
            "blocklist_match": hit,
        })

    print(f"\n[+] {len(records)} file(s) hashed" + (f", {hits} blocklist match(es)." if blocklist else "."))
    if args.output:
        write_report(records, Path(args.output))
        print(f"[+] Report written to {args.output}")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())

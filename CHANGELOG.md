# Changelog

## [2.0.0] — 2026-11-26

### Added
- Proper CLI with `argparse` (the interactive prompt remains as a fallback when no path is given)
- Directory scanning (recursive) — hash whole trees in one run
- All algorithms computed in a **single read pass** per file
- SHA-512, SHA3-256, and BLAKE2b alongside MD5, SHA-1, SHA-256; `--algo` selection
- `--verify` mode: compare a file against a known hash, algorithm auto-detected from hash length
- `--baseline` / `--check`: file integrity monitoring — snapshot a directory into a JSON manifest and later report MODIFIED / MISSING / NEW files
- `--blocklist`: flag files matching a known-bad hash list (offline malware-hash checking)
- `--output`: export results to JSON, CSV, or TXT
- VirusTotal lookup link printed per file
- Script-friendly exit codes (0 clean, 1 findings, 2 usage/file error)
- Unit tests (stdlib `unittest`) and GitHub Actions CI for Python 3.10–3.12

### Changed
- Main script renamed `hash-checker.py` → `hash_checker.py` (importable module name)
- Errors are reported per file without aborting the whole scan

## [1.0.0] — 2026-07-05

### Added
- Initial release: interactive MD5 / SHA-1 / SHA-256 calculator for a single file, chunk-based reading

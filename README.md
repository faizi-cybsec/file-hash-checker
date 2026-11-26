# 🔐 File Integrity & Hash Checker

A zero-dependency Python command-line tool that generates cryptographic hashes to verify file integrity, monitor directories for tampering, and flag known-bad files — supporting digital forensics and SOC triage workflows.

![Python](https://img.shields.io/badge/Python-3.10+-blue)
![Domain](https://img.shields.io/badge/Domain-Cybersecurity-red)
![Status](https://img.shields.io/badge/Status-Active-success)
![License](https://img.shields.io/badge/License-MIT-green)

---

## 📌 Overview

The **File Integrity & Hash Checker** started as a simple hash calculator and, in **v2.0.0**, grew into a small integrity-monitoring tool:

- Hash single files or whole directory trees (all algorithms computed in **one read pass** per file)
- **Verify** a file against a known-good hash
- **Baseline** a directory into a manifest, then **check** it later for modified, missing, or newly added files — the core idea behind file integrity monitoring (FIM) in real SOC tooling
- **Blocklist mode**: flag any file whose hash appears in a known-bad hash list (offline malware-hash / IOC checking)

Built with the Python standard library only — no `pip install` of third-party packages needed.

---

## ✨ Features

- ✅ MD5, SHA-1, SHA-256, SHA-512, SHA3-256 and BLAKE2b
- ✅ Directory scanning (recursive)
- ✅ `--verify` mode with automatic algorithm detection from hash length
- ✅ `--baseline` / `--check` file-integrity monitoring with clear MODIFIED / MISSING / NEW reporting and script-friendly exit codes
- ✅ `--blocklist` known-bad hash flagging
- ✅ VirusTotal lookup link printed for every SHA-256
- ✅ Export results to JSON, CSV, or TXT (`--output`)
- ✅ Unit tests + GitHub Actions CI

---

## 🚀 Getting Started

### Prerequisites

- Python 3.10 or newer

### Installation

```bash
git clone https://github.com/faizi-cybsec/file-hash-checker.git
cd file-hash-checker
```

### Usage

```bash
# Hash one file (MD5, SHA-1, SHA-256 by default)
python hash_checker.py sample.exe

# Hash a whole directory, choose algorithms, save a JSON report
python hash_checker.py ./downloads --algo sha256 --algo sha512 --output report.json

# Verify a file against a known hash (algorithm auto-detected)
python hash_checker.py sample.exe --verify 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08

# Create an integrity baseline of a directory
python hash_checker.py ./config --baseline baseline.json

# Later: check the directory against the baseline
python hash_checker.py --check baseline.json

# Flag files matching a known-bad hash list (one hash per line)
python hash_checker.py ./downloads --blocklist known_bad_hashes.txt
```

Run `python hash_checker.py --help` for the full option list. With no arguments, the tool prompts for a path, as v1 did.

**Exit codes:** `0` = clean / verified, `1` = mismatch, tampering, or blocklist hit found, `2` = usage or file error — so the tool composes cleanly in scripts.

---

## 💻 Example Output

```
== sample.exe ==
MD5       8d777f385d3dfec8815d20f7496026dc
SHA1      a94a8fe5ccb19ba61c4c0873d391e987982fbbd3
SHA256    9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08
VirusTotal  https://www.virustotal.com/gui/file/9f86d081884c7d659a2feaa0c55ad015...

[+] 1 file(s) hashed.
```

Baseline check after a file is tampered with:

```
Baseline check of ./config (created 2026-11-26T09:31:08+00:00):
  OK       11 file(s) unchanged
  MODIFIED  app.conf

[!] 1 difference(s) found.
```

---

## 📂 Project Structure

```
file-hash-checker/
├── hash_checker.py            # the tool (single file, stdlib only)
├── tests/
│   └── test_hash_checker.py   # unit tests (unittest)
├── .github/workflows/ci.yml   # CI: tests on Python 3.10–3.12
├── CHANGELOG.md
├── README.md
└── LICENSE
```

## 🧪 Tests

```bash
python -m unittest discover -s tests -v
```

---

## 🔒 Cybersecurity Applications

- File integrity verification for downloads and evidence files
- Tamper detection on watched directories (baseline vs. current state)
- Malware triage: hash a suspicious file, check the blocklist, follow the VirusTotal link
- Incident response and basic digital forensics workflows

## 📚 Learning Outcomes

- Cryptographic hashing and why MD5/SHA-1 are identification-only, not security controls
- File integrity monitoring concepts used by real HIDS/SOC tooling
- CLI design with `argparse`, exit codes, and machine-readable output
- Testing and CI for a security tool

## 🗺️ Roadmap

- [x] Hash verification mode
- [x] Directory scanning
- [x] Export results (JSON/CSV/TXT)
- [x] Additional algorithms
- [ ] Watch mode (periodic re-check of a baseline)
- [ ] Optional VirusTotal API lookup

---

## 🤝 Contributions

Contributions, suggestions, and feedback are welcome. Feel free to fork the repository and submit improvements.

## 📄 License

This project is licensed under the MIT License.

## 👨‍💻 Author

**Faizan Ahmed** — Aspiring SOC Analyst | BS Cyber Security Student @ Superior University

GitHub: [faizi-cybsec](https://github.com/faizi-cybsec)

If you found this project useful, consider giving it a ⭐ on GitHub.

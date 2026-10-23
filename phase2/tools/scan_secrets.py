#!/usr/bin/env python3
"""Secret scan for source control and evidence (SR-10, NFR-05).

Usage:
  python tools/scan_secrets.py                 scan every file git tracks or would add
  python tools/scan_secrets.py PATH [PATH...]  scan the given files or directories

Exit code 0 = no findings. A finding prints file:line and the rule name, never
the matched text, so the scan output itself cannot leak a secret.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {".git", ".venv", "__pycache__", ".pytest_cache", "node_modules"}
KEY_FILE_SUFFIXES = {".pem", ".key", ".p12", ".pfx", ".jks"}

# Built by concatenation so this file does not match its own rules.
RULES = [
    ("private-key-block", re.compile("-----BEGIN " r"(?:[A-Z0-9]+ )*" "PRIVATE KEY-----")),
    ("aws-access-key-id", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,}\b")),
    ("password-assignment", re.compile(
        r"""(?i)\b(?:password|passwd|passphrase|secret_key|api_key)\b\s*[:=]\s*["'][^"'\s]{6,}["']""")),
    ("bearer-token-literal", re.compile(r"Bearer\s+[A-Za-z0-9._~+/=-]{24,}")),
]


def candidate_files(paths: list[str]) -> list[Path]:
    if paths:
        out = []
        for p in map(Path, paths):
            if p.is_dir():
                out += [f for f in p.rglob("*") if f.is_file()
                        and not SKIP_DIRS.intersection(f.parts)]
            elif p.is_file():
                out.append(p)
        return out
    try:
        top = subprocess.run(["git", "rev-parse", "--show-toplevel"], cwd=ROOT,
                             capture_output=True, text=True, check=True).stdout.strip()
        listed = subprocess.run(["git", "ls-files", "--cached", "--others", "--exclude-standard"],
                                cwd=top, capture_output=True, text=True, check=True).stdout
        return [Path(top) / line for line in listed.splitlines()
                if line and (Path(top) / line).is_file()]
    except (OSError, subprocess.CalledProcessError):
        return candidate_files([str(ROOT)])          # not a git checkout (e.g. a zip)


def scan(files: list[Path]) -> list[tuple[str, int, str]]:
    findings = []
    for f in files:
        if f.suffix.lower() in KEY_FILE_SUFFIXES:
            findings.append((str(f), 0, "key-file-in-tree"))
            continue
        try:
            text = f.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue                                   # binary file
        for lineno, line in enumerate(text.splitlines(), start=1):
            if "scan:allow" in line:
                continue
            for name, rx in RULES:
                if rx.search(line):
                    findings.append((str(f), lineno, name))
    return findings


def main(argv: list[str]) -> int:
    files = candidate_files(argv)
    findings = scan(files)
    for path, lineno, rule in findings:
        print(f"{path}:{lineno}: {rule}")
    print(f"scanned {len(files)} files: {'FAIL, ' + str(len(findings)) + ' finding(s)' if findings else 'PASS, no secrets found'}")
    return 1 if findings else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

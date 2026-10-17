#!/usr/bin/env python3
"""One command for the whole Merged Phase 2 package (NFR-01, P2-11).

Usage:  python run_all.py            (from the phase2 folder)

Writes every log and evidence file under evidence/ and exits 0 only if every
step passes.
"""
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
EVIDENCE = ROOT / "evidence"
PY = sys.executable

STEPS = [
    ("acceptance, attack, fault, quality and end-to-end tests",
     [PY, "-W", "ignore::DeprecationWarning", "-m", "unittest", "discover", "-s", "tests",
      "-t", ".", "-v"], "unittest.log"),
    ("traceability consistency check", [PY, "tools/check_trace.py"], "trace_check.log"),
    ("generated tables are up to date", [PY, "tools/build_docs.py", "--check"], "build_docs.log"),
    ("secret scan of the repository", [PY, "tools/scan_secrets.py"], "secret_scan.log"),
    ("vehicle five-test walkthrough",
     [PY, "walkthrough.py", "--evidence", "evidence/walkthrough"], "walkthrough.log"),
    ("end-to-end tampered firmware trace",
     [PY, "e2e_trace.py", "--evidence", "evidence/walkthrough"], "e2e_trace.log"),
    ("verification latency (NFR-03)",
     [PY, "tools/bench_verify.py", "--repeat", "5", "--out", "evidence/latency.csv"], "latency.log"),
    ("secret scan of the evidence just written", [PY, "tools/scan_secrets.py", "evidence"],
     "evidence_scan.log"),
]


def main() -> int:
    EVIDENCE.mkdir(exist_ok=True)
    failed = []
    summary = []
    for title, cmd, log in STEPS:
        print(f"== {title}")
        proc = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True)
        output = proc.stdout + proc.stderr
        (EVIDENCE / log).write_text(output, encoding="utf-8")
        tail = output.strip().splitlines()[-1] if output.strip() else ""
        line = f"   {'ok' if proc.returncode == 0 else 'FAILED'}: {tail}   (evidence/{log})"
        print(line)
        summary.append(f"{title}\n{line}")
        if proc.returncode:
            failed.append(title)
    verdict = "PASS" if not failed else "FAIL -> " + ", ".join(failed)
    print("\nPHASE PACKAGE:", verdict)
    (EVIDENCE / "run_all.log").write_text("\n".join(summary) + f"\n\nPHASE PACKAGE: {verdict}\n",
                                          encoding="utf-8")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())

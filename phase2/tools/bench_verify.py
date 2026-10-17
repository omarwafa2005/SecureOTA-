#!/usr/bin/env python3
"""Verification latency measurement (NFR-03).

Usage:  python tools/bench_verify.py [--repeat 7] [--out evidence/latency.csv]

For each defined artifact size it measures, on this machine:
  sha256_ms    SHA-256 of the image alone
  pipeline_ms  gateway.process_update: signature + checks + in-memory download
               + length/SHA-256 + ECU stage (which hashes again and writes the slot)
It reports median and max over --repeat runs. Numbers are for comparison
between runs on the same machine, not a performance claim.
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import platform
import statistics
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from vehicle.testkit import Bench, firmware  # noqa: E402

SIZES = {"64KiB": 64 * 1024, "1MiB": 1024 * 1024, "16MiB": 16 * 1024 * 1024}


def measure(repeat: int, sizes: dict[str, int] = SIZES) -> list[dict]:
    rows = []
    for label, size in sizes.items():
        digest_ms, pipeline_ms = [], []
        for _ in range(repeat):
            image = firmware("ECU-A", 2, size)
            t0 = time.perf_counter()
            hashlib.sha256(image).hexdigest()
            digest_ms.append((time.perf_counter() - t0) * 1000)
            with tempfile.TemporaryDirectory() as tmp:
                bench = Bench(tmp)
                env, _ = bench.target("ECU-A", 2, image=image)
                fetch = bench.repo.fetcher(chunk_size=64 * 1024)
                t0 = time.perf_counter()
                result = bench.gateway.process_update(env, fetch)
                pipeline_ms.append((time.perf_counter() - t0) * 1000)
                if not result.ok:
                    raise RuntimeError(f"pipeline failed for {label}: {result.reason.value}")
        rows.append({"size": label, "bytes": size, "runs": repeat,
                     "sha256_median_ms": round(statistics.median(digest_ms), 3),
                     "sha256_max_ms": round(max(digest_ms), 3),
                     "pipeline_median_ms": round(statistics.median(pipeline_ms), 3),
                     "pipeline_max_ms": round(max(pipeline_ms), 3),
                     "python": platform.python_version(), "machine": platform.machine()})
    return rows


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--repeat", type=int, default=7)
    ap.add_argument("--out", type=Path)
    args = ap.parse_args()
    rows = measure(args.repeat)
    for r in rows:
        print(f"{r['size']:>6}: sha256 median {r['sha256_median_ms']:9.3f} ms | "
              f"pipeline median {r['pipeline_median_ms']:9.3f} ms (max {r['pipeline_max_ms']:.3f})")
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        with open(args.out, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(rows[0]))
            w.writeheader()
            w.writerows(rows)
        print(f"written: {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

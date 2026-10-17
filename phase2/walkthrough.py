#!/usr/bin/env python3
"""Student 1 reproducible five-test walkthrough (Week 6 evidence, review slot 0:00-1:00).

Usage:  python walkthrough.py [--evidence evidence/walkthrough]

Each scenario runs on a fresh simulated vehicle and prints the observable
outcome plus the final slot/version, so a reviewer can tell pass or fail
without asking the author.
"""
from __future__ import annotations

import argparse
import json
import sys
import tempfile
from pathlib import Path

from vehicle import Reason, VehicleConditions
from vehicle.testkit import SAFE, Bench


def s_normal(b: Bench):
    """ACC-06 | FR-03 FR-04 FR-09: v1 -> v2 on ECU-A with health confirmation."""
    cid = "walk-acc06"
    env, _ = b.target("ECU-A", 2)
    steps = [b.gateway.process_update(env, b.fetch(), cid).reason,
             b.gateway.activate("ECU-A", SAFE, cid).reason]
    b.ecus["ECU-A"].boot(cid)
    steps.append(b.ecus["ECU-A"].confirm_health(True, cid).reason)
    return steps, ("B", 2, "CONFIRMED"), steps == [Reason.OK] * 3


def s_tampered(b: Bench):
    """AT-01 | T-01 SR-02: one flipped byte in transit."""
    env, image = b.target("ECU-A", 2)
    evil = bytearray(image); evil[100] ^= 0xFF
    r = b.gateway.process_update(env, b.fetch(serve=bytes(evil)), "walk-at01")
    return [r.reason], ("A", 1, "IDLE"), r.reason is Reason.DIGEST_MISMATCH


def s_downgrade(b: Bench):
    """AT-04 | T-04 SR-06: properly signed v2 offered after v3 is confirmed."""
    b.install("ECU-A", 3)
    env, _ = b.target("ECU-A", 2)
    r = b.gateway.process_update(env, b.fetch(), "walk-at04")
    return [r.reason], ("B", 3, "CONFIRMED"), r.reason is Reason.ROLLBACK_REJECTED


def s_moving(b: Bench):
    """FT-05 | F-05 SAF-03: activation requested at 42 km/h, then again when parked."""
    env, _ = b.target("ECU-A", 2)
    first = [b.gateway.process_update(env, b.fetch(), "walk-ft05").reason]
    moving = b.gateway.activate("ECU-A", VehicleConditions(speed_kph=42.0, gear="D"), "walk-ft05")
    first.append(moving.reason)
    ok = moving.reason is Reason.ACTIVATION_POSTPONED and b.ecus["ECU-A"].active_slot == "A"
    parked = b.gateway.activate("ECU-A", SAFE, "walk-ft05")
    first.append(parked.reason)
    return first, ("B", 2, "INSTALLED"), ok and parked.ok


def s_unhealthy(b: Bench):
    """FT-04 | F-04 SAF-05 FR-10: new image boots but fails its health check."""
    cid = "walk-ft04"
    env, _ = b.target("ECU-A", 2)
    steps = [b.gateway.process_update(env, b.fetch(), cid).reason,
             b.gateway.activate("ECU-A", SAFE, cid).reason]
    b.ecus["ECU-A"].boot(cid)
    steps.append(b.ecus["ECU-A"].confirm_health(False, cid).reason)
    return steps, ("A", 1, "ROLLED_BACK"), steps[-1] is Reason.HEALTH_FAILED


SCENARIOS = [("ACC-06", s_normal), ("AT-01", s_tampered), ("AT-04", s_downgrade),
             ("FT-05", s_moving), ("FT-04", s_unhealthy)]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", type=Path, help="directory to write per-scenario JSON evidence")
    args = ap.parse_args()
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)

    failures = 0
    print(f"{'Test':7} {'Result':6} {'Outcome codes':58} {'Final ECU-A (slot, ver, state)'}")
    print("-" * 110)
    for test_id, fn in SCENARIOS:
        with tempfile.TemporaryDirectory() as tmp:
            bench = Bench(tmp)
            codes, expected, ok = fn(bench)
            ecu = bench.ecus["ECU-A"]
            final = (ecu.active_slot, ecu.active_version, ecu.update_state.value)
            passed = ok and final == expected and ecu.slot_image_valid(ecu.active_slot)
            failures += not passed
            print(f"{test_id:7} {'PASS' if passed else 'FAIL':6} "
                  f"{' -> '.join(c.value for c in codes):58} {final}")
            if args.evidence:
                record = {"test_id": test_id, "description": fn.__doc__.strip(),
                          "passed": passed, "outcomes": [c.value for c in codes],
                          "expected_final": list(expected), "final": list(final),
                          "ecus": {k: e.report() for k, e in bench.ecus.items()},
                          "audit_events": bench.audit.events}
                (args.evidence / f"{test_id}.json").write_text(json.dumps(record, indent=2))
    print("-" * 110)
    print("ALL PASS" if not failures else f"{failures} FAILED")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""End-to-end tampered-firmware trace for the final review (slot 3:15-4:15).

Usage:  python e2e_trace.py [--evidence evidence/walkthrough]

Walks the evidence chain Asset -> Threat -> Risk -> Requirement -> Control ->
Component -> Test -> Evidence for one critical risk (B-03 / T-01): firmware
is replaced in backend storage after it was signed. Prints each link and
writes evidence/walkthrough/AT-18.json.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import tempfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT))

from tests.fleet import Fleet  # noqa: E402
from vehicle import Reason  # noqa: E402
from vehicle.testkit import VEHICLE_ID, firmware  # noqa: E402


def row(name: str, key: str, value: str) -> dict:
    with open(ROOT / "trace" / name, newline="", encoding="utf-8") as f:
        return next(r for r in csv.DictReader(f) if r[key] == value)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--evidence", type=Path)
    args = ap.parse_args()

    asset, threat = row("assets.csv", "id", "A-01"), row("threats.csv", "id", "B-03")
    req = row("requirements.csv", "id", "SR-02")
    print(f"Asset        {asset['id']} {asset['name']}: integrity {asset['integrity']}")
    print(f"Threat       {threat['id']} {threat['title']} ({threat['stride']}, {threat['attacker']})")
    print(f"Risk         {threat['likelihood']} x {threat['impact']} = {threat['score']} ({threat['class']})")
    print(f"Requirement  {req['id']}: {req['statement']}")
    print(f"Control      {threat['prevention']}")
    print(f"Component    {req['component']}")

    with tempfile.TemporaryDirectory() as tmp:
        fleet = Fleet(tmp)
        rid = fleet.release("ECU-A", 2, cid="trace-rel-0001")
        cmp_id = fleet.campaign([rid], cid="trace-cmp-0001")
        art_id = fleet.backend._db["releases"][rid]["artifact_id"]
        evil = bytearray(firmware("ECU-A", 2))
        evil[4096] ^= 0x01
        fleet.backend._blobs[art_id] = bytes(evil)          # compromised object storage
        before = fleet.bench.snapshot()
        cid = "trace-at18-0001"
        result = fleet.poll_and_stage(cid)["ECU-A"]
        unchanged = fleet.bench.snapshot() == before
        status = fleet.backend.campaign_status(fleet.p["operator"], cmp_id, cid)["assignments"][0]
        passed = (result.reason is Reason.DIGEST_MISMATCH and unchanged
                  and status["state"] == "REJECTED")
        ecu = fleet.bench.ecus["ECU-A"]
        record = {
            "test_id": "AT-18", "passed": passed,
            "chain": {"asset": "A-01", "threat": "B-03", "risk": int(threat["score"]),
                      "requirement": "SR-02", "control": threat["prevention"],
                      "component": req["component"]},
            "vehicle_result": result.public(),
            "vehicle_state_unchanged": unchanged,
            "ecu_a_final": {"active_slot": ecu.active_slot, "active_version": ecu.active_version,
                            "update_state": ecu.update_state.value},
            "backend_assignment": status,
            "vehicle_events": fleet.bench.audit.find(correlation_id=cid),
            "backend_events": fleet.backend.audit.query(correlation_id=cid),
            "vehicle_id": VEHICLE_ID,
        }
    print(f"Test         AT-18 -> {result.reason.value}; vehicle state unchanged: {unchanged}; "
          f"backend assignment: {status['state']}")
    if args.evidence:
        args.evidence.mkdir(parents=True, exist_ok=True)
        (args.evidence / "AT-18.json").write_text(json.dumps(record, indent=2), encoding="utf-8")
        print(f"Evidence     {args.evidence / 'AT-18.json'}")
    print("PASS" if passed else "FAIL")
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())

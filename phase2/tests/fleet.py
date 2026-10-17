"""Shared fixture: backend + signing service + trust store + simulated vehicle.

Connects the three work packages for integration tests: the OEM backend
(Student 2) signs offers through the signing service (Student 3), and the
vehicle gateway (Student 1) trusts only release keys from a root-signed key
set. Tokens and keys are random per run; nothing secret is committed (SR-10).
"""
from __future__ import annotations

import secrets
import tempfile
import unittest
from pathlib import Path

from oem_backend import Authenticator, BackendService, Principal
from security import SigningService, TrustStore, public_hex
from vehicle.gateway import Gateway
from vehicle.testkit import ECU_HW, VEHICLE_ID, Bench, firmware

ROOT_KEY = "root-key-1"
RELEASE_KEY = "release-key-1"
VEHICLE_KEY = "vehicle-key-" + VEHICLE_ID
OTHER_VEHICLE = "VIN-SIM-0002"
YEAR = 365 * 24 * 3600

PRINCIPALS = {
    "registrar": Principal("alice.registrar", frozenset({"registrar"})),
    "creator": Principal("bob.creator", frozenset({"release_creator"})),
    "approver": Principal("carol.approver", frozenset({"release_approver"})),
    "operator": Principal("dave.operator", frozenset({"campaign_operator"})),
    "auditor": Principal("erin.auditor", frozenset({"auditor"})),
    "both": Principal("mallory.creator-approver",
                      frozenset({"release_creator", "release_approver"})),
    "vehicle": Principal("gw:" + VEHICLE_ID, frozenset({"vehicle"}), VEHICLE_ID),
    "other_vehicle": Principal("gw:" + OTHER_VEHICLE, frozenset({"vehicle"}), OTHER_VEHICLE),
}


class Fleet:
    def __init__(self, root):
        self.root = Path(root)
        self.bench = Bench(self.root / "vehicle")
        self.clock = self.bench.clock
        self.signer = SigningService(clock=self.clock)
        self.signer.generate(ROOT_KEY, "root")
        self.signer.generate(RELEASE_KEY, "release")
        self.signer.generate(VEHICLE_KEY, "vehicle")
        self.backend = BackendService(signer=self.signer, release_key_id=RELEASE_KEY,
                                      clock=self.clock)
        self.auth = Authenticator()
        self.tokens = {}
        for name, principal in PRINCIPALS.items():
            self.tokens[name] = secrets.token_urlsafe(32)
            self.auth.add(self.tokens[name], principal)
        self.p = PRINCIPALS
        self.trust = TrustStore(root_key_id=ROOT_KEY, root_public=self.signer.public(ROOT_KEY),
                                state_dir=self.bench.root, clock=self.clock)
        keyset = self.signer.sign_keyset(version=1, expires_at=int(self.clock()) + YEAR,
                                         include={RELEASE_KEY: "release", VEHICLE_KEY: "vehicle"},
                                         root_key_id=ROOT_KEY)
        assert self.trust.apply(keyset) is None
        self.gateway = self.make_gateway()
        self.backend.register_vehicle(self.p["registrar"], {
            "vehicle_id": VEHICLE_ID,
            "ecus": [{"ecu_id": e, "hardware_id": hw} for e, hw in ECU_HW.items()],
            "manifest_key_id": VEHICLE_KEY,
            "manifest_public_key": public_hex(self.signer.public(VEHICLE_KEY))}, "setup-0001")
        self.backend.register_vehicle(self.p["registrar"], {
            "vehicle_id": OTHER_VEHICLE,
            "ecus": [{"ecu_id": "ECU-A", "hardware_id": "HW-A-REV1"}],
            "manifest_key_id": "vehicle-key-" + OTHER_VEHICLE,
            "manifest_public_key": "00" * 32}, "setup-0002")

    def make_gateway(self) -> Gateway:
        """The vehicle trusts only release-role keys from the current key set (SR-17)."""
        return Gateway(vehicle_id=VEHICLE_ID, ecus=self.bench.ecus.values(),
                       trusted_keys=self.trust.keys_for("release"),
                       revoked_key_ids=self.trust.revoked, state_dir=self.bench.root,
                       manifest_key=self.signer.provision_vehicle_key(VEHICLE_KEY),
                       manifest_key_id=VEHICLE_KEY, clock=self.clock,
                       monotonic=self.bench.mono, audit=self.bench.audit)

    # ------------------------------------------------------------ backend side
    def release(self, ecu_id: str = "ECU-A", version: int = 2, cid: str = "rel-00001") -> str:
        art = self.backend.upload_artifact(self.p["creator"], firmware(ecu_id, version), ecu_id,
                                           ECU_HW[ecu_id], cid)
        rid = self.backend.create_release(self.p["creator"], {"artifact_id": art["artifact_id"],
                                                              "version": version}, cid)["release_id"]
        self.backend.approve_release(self.p["approver"], rid, cid)
        return rid

    def campaign(self, release_ids, targets=(VEHICLE_ID,), start=True, cid="cmp-00001", **extra):
        body = {"release_ids": list(release_ids), "targets": list(targets),
                "policy": {"expires_in_s": 7 * 24 * 3600, "require_safe_state": True}, **extra}
        cmp_id = self.backend.create_campaign(self.p["operator"], body, cid)["campaign_id"]
        if start:
            self.backend.start_campaign(self.p["operator"], cmp_id, cid)
        return cmp_id

    # ------------------------------------------------------------ vehicle side
    def report(self, campaign_id, ecu_id, outcome, metadata_version, cid, reason=""):
        body = {"event_id": "evt-" + secrets.token_hex(8), "campaign_id": campaign_id,
                "ecu_id": ecu_id, "outcome": outcome, "metadata_version": metadata_version}
        if reason:
            body["reason"] = reason
        return self.backend.report_event(self.p["vehicle"], VEHICLE_ID, body, cid)

    def poll_and_stage(self, cid: str = "veh-00001") -> dict:
        """Gateway pulls instructions, verifies, downloads, stages, reports each outcome."""
        out = {}
        instr = self.backend.get_instructions(self.p["vehicle"], VEHICLE_ID, cid)
        for bundle in instr["bundles"]:
            results = self.gateway.process_bundle(
                bundle, self.backend.fetcher(self.p["vehicle"], cid), cid)
            for env in bundle["targets"]:
                ecu_id = env["signed"]["ecu_id"]
                r = results.get(ecu_id) or results["*"]
                outcome = "STAGED" if r.ok else "REJECTED"
                self.report(bundle["campaign_id"], ecu_id, outcome,
                            env["signed"]["metadata_version"], cid,
                            "" if r.ok else r.reason.value)
                out[ecu_id] = r
        return out


class FleetTestCase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.fleet = Fleet(self._tmp.name)
        self.backend = self.fleet.backend
        self.p = self.fleet.p

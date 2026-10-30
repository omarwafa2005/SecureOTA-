"""End-to-end tests across backend, signing service and vehicle (all workstreams).

Docstring format: <test ID> | <threat IDs or -> | <requirement IDs>.
AT-18 is the tampered-firmware trace used in the final review (slot 3:15-4:15).
"""
from oem_backend import ApiError
from vehicle import Reason
from vehicle.testkit import SAFE, VEHICLE_ID, firmware

from .fleet import FleetTestCase


class EndToEndTests(FleetTestCase):

    def full_install(self, cid):
        ra = self.fleet.release("ECU-A", 2)
        rb = self.fleet.release("ECU-B", 2, cid="rel-00002")
        cmp_id = self.fleet.campaign([ra, rb], dependencies={"ECU-A": ["ECU-B"]})
        staged = self.fleet.poll_and_stage(cid)
        self.assertTrue(all(r.ok for r in staged.values()), staged)
        mv = {a["ecu_id"]: a["metadata_version"] for a in self.backend._db["assignments"].values()}
        for ecu_id in ("ECU-B", "ECU-A"):                              # dependency order
            ecu = self.fleet.bench.ecus[ecu_id]
            self.assertTrue(self.fleet.gateway.activate(ecu_id, SAFE, cid).ok)
            self.fleet.report(cmp_id, ecu_id, "INSTALLED", mv[ecu_id], cid)
            ecu.boot(cid)
            self.assertTrue(ecu.confirm_health(True, cid).ok)
            self.fleet.report(cmp_id, ecu_id, "CONFIRMED", mv[ecu_id], cid)
        return cmp_id

    def test_E2E_01_campaign_to_confirmed_on_two_ecus(self):
        """E2E-01 | - | FR-02 FR-03 FR-04 FR-08 FR-09 FR-12 SR-20"""
        cid = "e2e-01-cid-0001"
        cmp_id = self.full_install(cid)
        manifest = self.fleet.gateway.build_manifest(cid)
        self.assertTrue(self.backend.submit_manifest(self.p["vehicle"], VEHICLE_ID, manifest,
                                                     cid)["accepted"])
        inventory = self.backend._db["vehicles"][VEHICLE_ID]["ecus"]
        self.assertEqual({e: (r["active_version"], r["update_state"]) for e, r in inventory.items()},
                         {"ECU-A": (2, "CONFIRMED"), "ECU-B": (2, "CONFIRMED")})
        status = self.backend.campaign_status(self.p["operator"], cmp_id, cid)
        self.assertEqual({a["state"] for a in status["assignments"]}, {"CONFIRMED"})
        # the vehicle is now at v2 everywhere -> no further instructions (FR-02 eligibility)
        self.assertEqual(self.backend.get_instructions(self.p["vehicle"], VEHICLE_ID, cid)["bundles"], [])
        for ecu in self.fleet.bench.ecus.values():
            self.assertEqual((ecu.active_slot, ecu.confirmed_version), ("B", 2))

    def test_AT_18_firmware_replaced_in_backend_storage_after_signing(self):
        """AT-18 | T-01 B-03 | SR-02 SR-03"""
        rid = self.fleet.release("ECU-A", 2)
        cmp_id = self.fleet.campaign([rid])
        art_id = self.backend._db["releases"][rid]["artifact_id"]
        evil = bytearray(firmware("ECU-A", 2))
        evil[4096] ^= 0x01                                   # one bit, same length
        self.backend._blobs[art_id] = bytes(evil)            # compromised object storage
        before = self.fleet.bench.snapshot()
        cid = "at18-tamper-0001"
        result = self.fleet.poll_and_stage(cid)["ECU-A"]
        # vehicle: rejected at download, nothing staged, trusted state byte-identical
        self.assertIs(result.reason, Reason.DIGEST_MISMATCH)
        self.assertEqual(result.public(), {"status": "REJECTED", "reason": "DIGEST_MISMATCH",
                                           "correlation_id": cid})
        self.assertEqual(self.fleet.bench.snapshot(), before)
        self.assertFalse(self.fleet.bench.ecus["ECU-A"].slot_path("B").exists())
        # evidence on both sides, joined by one correlation ID
        veh = self.fleet.bench.audit.find(correlation_id=cid, outcome="REJECTED")
        self.assertEqual([(e["component"], e["action"], e["reason"]) for e in veh],
                         [("gateway", "download", "DIGEST_MISMATCH")])
        status = self.backend.campaign_status(self.p["operator"], cmp_id, cid)["assignments"][0]
        self.assertEqual((status["state"], status["reason"]), ("REJECTED", "DIGEST_MISMATCH"))
        actions = [e["action"] for e in self.backend.audit.query(correlation_id=cid)]
        self.assertEqual(actions, ["get_instructions", "download_artifact", "report_event",
                                   "view_status"])

    def test_AT_19_modified_foreign_or_stale_manifest_rejected(self):
        """AT-19 | T-11 V-02 | SR-20"""
        cid = "at19-cid-00001"
        veh = self.p["vehicle"]
        good = self.fleet.gateway.build_manifest(cid)
        self.assertTrue(self.backend.submit_manifest(veh, VEHICLE_ID, good, cid)["accepted"])
        self.fleet.clock.advance(60)
        fresh = self.fleet.gateway.build_manifest(cid)
        modified = {**fresh, "signed": {**fresh["signed"], "ecus": [
            dict(e, active_version=99) for e in fresh["signed"]["ecus"]]}}
        self.fleet.signer.generate("vehicle-key-rogue", "vehicle")
        from vehicle.metadata import sign_envelope
        foreign = sign_envelope(fresh["signed"], self.fleet.signer._keys["vehicle-key-rogue"].private,
                                "vehicle-key-rogue")
        incomplete_payload = dict(fresh["signed"], ecus=fresh["signed"]["ecus"][:1])
        incomplete = sign_envelope(incomplete_payload,
                                   self.fleet.signer._keys[good["key_id"]].private, good["key_id"])
        cases = [("modified", modified, "VALIDATION_FAILED", "BAD_SIGNATURE"),
                 ("unknown key", foreign, "VALIDATION_FAILED", "UNTRUSTED_KEY"),
                 ("replayed", good, "CONFLICT", "STALE_MANIFEST"),
                 ("incomplete", incomplete, "VALIDATION_FAILED", "MANIFEST_INCOMPLETE")]
        before = {k: dict(v) for k, v in self.backend._db["vehicles"][VEHICLE_ID]["ecus"].items()}
        for name, env, category, code in cases:
            with self.subTest(name):
                with self.assertRaises(ApiError) as ctx:
                    self.backend.submit_manifest(veh, VEHICLE_ID, env, cid)
                self.assertEqual((ctx.exception.category, ctx.exception.code), (category, code))
                self.assertEqual(self.backend._db["vehicles"][VEHICLE_ID]["ecus"], before)
        self.assertTrue(self.backend.submit_manifest(veh, VEHICLE_ID, fresh, cid)["accepted"])

    def test_AT_23_database_edits_cannot_retarget_signed_content(self):
        """AT-23 | B-04 T-06 | SR-03 SR-07"""
        rid = self.fleet.release("ECU-A", 2)
        self.fleet.campaign([rid])
        self.backend.get_instructions(self.p["vehicle"], VEHICLE_ID, "at23-cid-0001")
        (assignment,) = self.backend._db["assignments"].values()
        signed = assignment["envelope"]["signed"]
        for field, value, reason in (("version", 3, Reason.BAD_SIGNATURE),
                                     ("vehicle_id", "VIN-SIM-0002", Reason.BAD_SIGNATURE),
                                     ("campaign_id", "CMP-9999", Reason.BAD_SIGNATURE)):
            with self.subTest(field):
                original = signed[field]
                signed[field] = value                         # edited in the database
                before = self.fleet.bench.snapshot()
                out = self.fleet.gateway.process_bundle(
                    self.backend.get_instructions(self.p["vehicle"], VEHICLE_ID, "at23-cid-0002")
                    ["bundles"][0], self.backend.fetcher(self.p["vehicle"], "at23-cid-0002"))
                self.assertIs(out["*"].reason, reason)
                self.assertEqual(self.fleet.bench.snapshot(), before)
                signed[field] = original
        self.assertTrue(self.fleet.poll_and_stage("at23-cid-0003")["ECU-A"].ok)

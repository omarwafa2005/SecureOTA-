"""Negative (attack) tests. Every rejection must leave trusted state unchanged.

Docstring format: <test ID> | <threat IDs> | <requirement IDs>.
"""
import math

from vehicle import Reason, UpdateState, VehicleConditions, verify_manifest
from vehicle.metadata import sign_envelope
from vehicle.testkit import SAFE, Signer, firmware

from .base import BenchTestCase


class AttackTests(BenchTestCase):

    def test_AT_01_tampered_firmware_rejected_before_staging(self):
        """AT-01 | T-01 | SR-02 SR-03"""
        env, image = self.bench.target("ECU-A", 2)
        evil = bytearray(image)
        evil[100] ^= 0xFF
        before = self.bench.snapshot()
        r = self.gw.process_update(env, self.bench.fetch(serve=bytes(evil)))
        self.assertRejected(r, Reason.DIGEST_MISMATCH)
        self.assertTrustedStateUnchanged(before)
        self.assertFalse(self.ecu_a.slot_path("B").exists())       # no staged file
        # the gateway itself rejects at download; the ECU never sees the image
        events = self.bench.audit.find(correlation_id=r.correlation_id, outcome="REJECTED")
        self.assertEqual([(e["component"], e["action"]) for e in events], [("gateway", "download")])

    def test_AT_01c_ecu_rejects_tampered_image_even_if_gateway_forwards_it(self):
        """AT-01 | T-01 | SR-02  (defence in depth at the ECU)"""
        env, image = self.bench.target("ECU-A", 2)
        before = self.bench.snapshot()
        r = self.ecu_a.stage(image[:-1] + b"\x00", env["signed"], "direct")
        self.assertRejected(r, Reason.DIGEST_MISMATCH)
        self.assertTrustedStateUnchanged(before)

    def test_AT_01b_metadata_changed_after_signing(self):
        """AT-01 | T-01 | SR-03"""
        env, _ = self.bench.target("ECU-A", 2)
        evil_image = firmware("ECU-A", 99)
        env["signed"]["sha256"] = __import__("hashlib").sha256(evil_image).hexdigest()
        before = self.bench.snapshot()
        self.assertRejected(self.gw.process_update(env, self.bench.fetch(serve=evil_image)),
                            Reason.BAD_SIGNATURE)
        self.assertTrustedStateUnchanged(before)
        self.assertEqual(self.bench.repo.requests, [])            # nothing downloaded

    def test_AT_02_unknown_and_revoked_keys_rejected(self):
        """AT-02 | T-02 | SR-03 SR-04"""
        before = self.bench.snapshot()
        rogue = Signer.generate("rogue-key")
        env, _ = self.bench.target("ECU-A", 2, signer=rogue)
        self.assertRejected(self.gw.process_update(env, self.bench.fetch()), Reason.UNTRUSTED_KEY)
        # rogue key reusing the trusted key id -> signature fails
        env, _ = self.bench.target("ECU-A", 2, signer=Signer(self.bench.release.key_id, rogue.private))
        self.assertRejected(self.gw.process_update(env, self.bench.fetch()), Reason.BAD_SIGNATURE)
        # revoked key
        self.bench.revoked.add(self.bench.release.key_id)
        self.restart()
        env, _ = self.bench.target("ECU-A", 2)
        self.assertRejected(self.gw.process_update(env, self.bench.fetch()), Reason.UNTRUSTED_KEY)
        self.assertTrustedStateUnchanged(before)

    def test_AT_03_replayed_older_metadata_rejected(self):
        """AT-03 | T-03 | SR-07"""
        old_env, _ = self.bench.target("ECU-A", 3)        # metadata_version 1, never applied
        new_env, _ = self.bench.target("ECU-A", 2)        # metadata_version 2
        self.assertTrue(self.gw.process_update(new_env, self.bench.fetch()).ok)
        before = self.bench.snapshot()
        self.assertRejected(self.gw.process_update(old_env, self.bench.fetch()),
                            Reason.REPLAYED_METADATA)
        self.assertTrustedStateUnchanged(before)
        # same metadata_version, different content -> inconsistent
        self.bench._metadata_version = 1
        twin, _ = self.bench.target("ECU-A", 4)
        self.assertRejected(self.gw.process_update(twin, self.bench.fetch()),
                            Reason.INCONSISTENT_METADATA)
        self.assertTrustedStateUnchanged(before)

    def test_AT_04_downgrade_rejected(self):
        """AT-04 | T-04 | SR-06"""
        self.bench.install("ECU-A", 3)
        before = self.bench.snapshot()
        self.assertRejected(self.bench.update("ECU-A", 2), Reason.ROLLBACK_REJECTED)
        self.assertRejected(self.bench.update("ECU-A", 3), Reason.ALREADY_INSTALLED)
        self.assertTrustedStateUnchanged(before)
        # ECU enforces it too, even if a faulty gateway forwarded it
        env, image = self.bench.target("ECU-A", 2)
        r = self.ecu_a.stage(image, env["signed"], "direct")
        self.assertRejected(r, Reason.ROLLBACK_REJECTED)
        self.assertTrustedStateUnchanged(before)

    def test_AT_05_wrong_target_rejected(self):
        """AT-05 | T-05 | SR-05"""
        before = self.bench.snapshot()
        env, _ = self.bench.target("ECU-A", 2, hardware_id="HW-A-REV1")
        self.assertRejected(self.gw.process_update(env, self.bench.fetch()), Reason.WRONG_TARGET)
        env, _ = self.bench.target("ECU-Z", 2)
        self.assertRejected(self.gw.process_update(env, self.bench.fetch()), Reason.WRONG_TARGET)
        # an ECU-B image addressed to ECU-A's identity still binds: ECU refuses foreign identity
        env, image = self.bench.target("ECU-B", 2)
        self.assertRejected(self.ecu_a.stage(image, env["signed"], "direct"), Reason.WRONG_TARGET)
        self.assertTrustedStateUnchanged(before)

    def test_AT_06_mixed_campaign_bundle_rejected_as_a_whole(self):
        """AT-06 | T-06 | SR-07"""
        before = self.bench.snapshot()
        good, _ = self.bench.target("ECU-A", 2)
        foreign, _ = self.bench.target("ECU-B", 2, campaign_id="CMP-OTHER")
        results = self.gw.process_bundle({"campaign_id": "CMP-2026-001",
                                          "targets": [good, foreign]}, self.bench.fetch())
        self.assertRejected(results["*"], Reason.INCONSISTENT_METADATA)
        self.assertEqual(self.bench.repo.requests, [])             # nothing downloaded
        other_vehicle, _ = self.bench.target("ECU-A", 2, vehicle_id="VIN-OTHER")
        self.assertRejected(self.gw.process_update(other_vehicle, self.bench.fetch()),
                            Reason.INCONSISTENT_METADATA)
        dup = self.gw.process_bundle({"campaign_id": "CMP-2026-001",
                                      "targets": [good, self.bench.target("ECU-A", 3)[0]]},
                                     self.bench.fetch())
        self.assertRejected(dup["*"], Reason.INCONSISTENT_METADATA)
        self.assertTrustedStateUnchanged(before)

    def test_AT_07_expired_metadata_rejected(self):
        """AT-07 | T-07 | SR-07  (assumes a trusted clock; see A-TIME in the spec)"""
        before = self.bench.snapshot()
        env, _ = self.bench.target("ECU-A", 2, expires_at=int(self.bench.clock()) - 1)
        self.assertRejected(self.gw.process_update(env, self.bench.fetch()), Reason.EXPIRED_METADATA)
        env, _ = self.bench.target("ECU-A", 2, expires_at=int(self.bench.clock()))
        self.assertRejected(self.gw.process_update(env, self.bench.fetch()), Reason.EXPIRED_METADATA)
        self.assertTrustedStateUnchanged(before)

    def test_AT_08_truncated_oversized_and_endless_downloads(self):
        """AT-08 | T-08 | SR-12 SR-02"""
        before = self.bench.snapshot()
        env, image = self.bench.target("ECU-A", 2)
        self.assertRejected(self.gw.process_update(env, self.bench.fetch(serve=image[:-10])),
                            Reason.LENGTH_MISMATCH)
        self.assertRejected(self.gw.process_update(env, self.bench.fetch(serve=image + b"X" * 10)),
                            Reason.ARTIFACT_TOO_LARGE)
        self.assertRejected(self.gw.process_update(env, self.bench.fetch(endless=True)),
                            Reason.ARTIFACT_TOO_LARGE)
        self.bench.repo.requests.clear()
        huge, _ = self.bench.target("ECU-A", 2, length=self.gw.max_artifact_bytes + 1)
        self.assertRejected(self.gw.process_update(huge, self.bench.fetch()), Reason.ARTIFACT_TOO_LARGE)
        self.assertEqual(self.bench.repo.requests, [])             # rejected before download
        self.assertTrustedStateUnchanged(before)

    def test_AT_09_slow_and_stalled_downloads_time_out(self):
        """AT-09 | T-09 | NFR-04"""
        before = self.bench.snapshot()
        env, _ = self.bench.target("ECU-A", 2)
        stall = self.gw.stall_timeout_s + 1
        r = self.gw.process_update(env, self.bench.fetch(stall_after=2048, stall_s=stall))
        self.assertRejected(r, Reason.DOWNLOAD_TIMEOUT)
        # slow-drip: every chunk on time, but total time exceeds the limit
        r = self.gw.process_update(env, self.bench.fetch(chunk_size=64, delay_s=self.gw.stall_timeout_s - 1))
        self.assertRejected(r, Reason.DOWNLOAD_TIMEOUT)
        # keep-alive of empty chunks does not count as progress
        def empty_keepalive(artifact_id, sha):
            while True:
                self.bench.mono.advance(1.0)
                yield b""
        self.assertRejected(self.gw.process_update(env, empty_keepalive), Reason.DOWNLOAD_TIMEOUT)
        self.assertTrustedStateUnchanged(before)
        self.assertTrue(self.gw.process_update(env, self.bench.fetch()).ok)   # normal speed still works

    def test_AT_11_modified_manifest_detected(self):
        """AT-11 | T-11 | FR-08 SR-13"""
        keys = {self.bench.vehicle_key.key_id: self.bench.vehicle_key.public}
        env = self.gw.build_manifest()
        env["signed"]["ecus"][0]["active_version"] = 999
        self.assertIs(verify_manifest(env, keys)[0], Reason.BAD_SIGNATURE)
        forged = sign_envelope({"vehicle_id": "VIN-SIM-0001", "ecus": []},
                               Signer.generate("x").private, self.bench.vehicle_key.key_id)
        self.assertIs(verify_manifest(forged, keys)[0], Reason.BAD_SIGNATURE)

    def test_AT_13_unsolicited_activation_ignored(self):
        """AT-13 | V-01 | SAF-10"""
        before = self.bench.snapshot()
        self.assertRejected(self.gw.activate("ECU-A", SAFE), Reason.INVALID_STATE)
        self.assertRejected(self.ecu_a.confirm_health(True, "x"), Reason.INVALID_STATE)
        self.assertEqual(self.ecu_a.boot(), "A")
        self.assertTrustedStateUnchanged(before)

    def test_AT_14_corrupted_staged_image_not_activated(self):
        """AT-14 | V-03 | SAF-07"""
        self.assertTrue(self.bench.update("ECU-A", 2).ok)
        path = self.ecu_a.slot_path("B")
        data = bytearray(path.read_bytes())
        data[10] ^= 0x01
        path.write_bytes(bytes(data))                      # bit flip in flash
        r = self.gw.activate("ECU-A", SAFE)
        self.assertRejected(r, Reason.STORAGE_ERROR)
        self.assertEqual((self.ecu_a.active_slot, self.ecu_a.active_version), ("A", 1))
        self.assertIs(self.ecu_a.update_state, UpdateState.REJECTED)
        self.assertTrue(self.bench.update("ECU-A", 3).ok)  # recovers on the next good update

    def test_AT_15_tampered_active_image_rolls_back_at_boot(self):
        """AT-15 | V-04 | SAF-09 SAF-05"""
        self.assertTrue(self.bench.update("ECU-A", 2).ok)
        self.assertTrue(self.gw.activate("ECU-A", SAFE, "c").ok)
        self.ecu_a.slot_path("B").write_bytes(firmware("ECU-A", 66))
        self.assertEqual(self.ecu_a.boot("c"), "A")
        self.assertIs(self.ecu_a.update_state, UpdateState.ROLLED_BACK)
        self.assertEqual(self.bench.audit.find(outcome="ROLLED_BACK")[0]["cause"], "ACTIVE_IMAGE_INTEGRITY")

    def test_AT_16_invalid_safety_inputs_block_activation(self):
        """AT-16 | V-05 | SAF-03 SAF-04"""
        self.assertTrue(self.bench.update("ECU-A", 2).ok)
        for bad in (VehicleConditions(speed_kph=-0.1), VehicleConditions(speed_kph=math.nan),
                    VehicleConditions(speed_kph=None), VehicleConditions(speed_kph=True),
                    VehicleConditions(battery_v=math.inf), VehicleConditions(battery_v="13"),
                    VehicleConditions(diagnostic_session="no")):
            with self.subTest(bad=bad):
                r = self.gw.activate("ECU-A", bad)
                self.assertIs(r.reason, Reason.ACTIVATION_POSTPONED)
                self.assertIs(self.ecu_a.update_state, UpdateState.STAGED)
                self.assertEqual(self.ecu_a.active_slot, "A")

    def test_AT_17_malformed_metadata_rejected(self):
        """AT-17 | T-01 T-08 | SR-03 SR-12"""
        before = self.bench.snapshot()
        cases = [dict(version="2"), dict(length=0), dict(sha256="ABC"), dict(version=True),
                 dict(extra_field="x")]
        for override in cases:
            with self.subTest(override=override):
                env, _ = self.bench.target("ECU-A", 2)
                payload = dict(env["signed"], **override)
                env = self.bench.release.sign(payload)       # validly signed but malformed
                self.assertRejected(self.gw.process_update(env, self.bench.fetch()),
                                    Reason.MALFORMED_METADATA)
        for env in (None, [], {"signed": {}, "key_id": "k"}, {"signed": {}, "key_id": 1, "sig": ""},
                    {"signed": {}, "key_id": self.bench.release.key_id, "sig": "zz"}):
            with self.subTest(env=env):
                self.assertRejected(self.gw.process_update(env, self.bench.fetch()),
                                    Reason.MALFORMED_METADATA)
        self.assertTrustedStateUnchanged(before)

"""Normal-flow acceptance tests for gateway and ECU functional requirements.

Each docstring starts with: <test ID> | <requirement IDs> | <use case>.
tools/check_trace.py reads these IDs to prove every Must requirement is tested.
"""
from vehicle import Reason, UpdateState, verify_manifest
from vehicle.ecu import sha256_hex
from vehicle.testkit import SAFE, firmware

from .base import BenchTestCase


class GatewayAndEcuAcceptance(BenchTestCase):

    def test_ACC_01_downloads_exact_artifact_named_by_metadata(self):
        """ACC-01 | FR-03 | UC-06"""
        env, image = self.bench.target("ECU-A", 2)
        result = self.gw.process_update(env, self.bench.fetch())
        self.assertTrue(result.ok, result)
        self.assertEqual(self.bench.repo.requests,
                         [(env["signed"]["artifact_id"], env["signed"]["sha256"])])
        staged = self.ecu_a.slot_path(self.ecu_a.inactive_slot).read_bytes()
        self.assertEqual(sha256_hex(staged), env["signed"]["sha256"])

    def test_ACC_02_stages_into_inactive_slot(self):
        """ACC-02 | FR-04 | UC-07"""
        self.assertEqual(self.ecu_a.active_slot, "A")
        self.assertTrue(self.bench.update("ECU-A", 2).ok)
        self.assertIs(self.ecu_a.update_state, UpdateState.STAGED)
        self.assertEqual(self.ecu_a.slot_record("B")["version"], 2)
        self.assertEqual(self.ecu_a.staged_version, 2)
        self.assertTrue(self.ecu_a.slot_image_valid("B"))

    def test_ACC_03_active_known_good_slot_preserved_until_activation(self):
        """ACC-03 | FR-05 | UC-07"""
        before_a = self.ecu_a.slot_path("A").read_bytes()
        self.assertTrue(self.bench.update("ECU-A", 2).ok)
        self.assertEqual(self.ecu_a.active_slot, "A")
        self.assertEqual(self.ecu_a.confirmed_slot, "A")
        self.assertEqual(self.ecu_a.active_version, 1)
        self.assertEqual(self.ecu_a.slot_path("A").read_bytes(), before_a)
        self.assertTrue(self.gw.activate("ECU-A", SAFE).ok)
        self.assertEqual(self.ecu_a.active_slot, "B")
        self.assertEqual(self.ecu_a.confirmed_slot, "A")   # still the fallback

    def test_ACC_04_all_update_states_are_recorded_with_correlation_ids(self):
        """ACC-04 | FR-06 | UC-07 UC-08 UC-09"""
        self.bench.install("ECU-A", 2)                          # STAGED, INSTALLED, CONFIRMED
        self.assertRejected(self.bench.update("ECU-A", 1), Reason.ROLLBACK_REJECTED)  # REJECTED
        self.assertTrue(self.bench.update("ECU-A", 3).ok)
        cid = "cid-fail-health"
        self.assertTrue(self.gw.activate("ECU-A", SAFE, cid).ok)
        self.ecu_a.confirm_health(False, cid)                    # ROLLED_BACK
        outcomes = {e["outcome"] for e in self.bench.audit.events}
        self.assertTrue({"STAGED", "INSTALLED", "CONFIRMED", "REJECTED", "ROLLED_BACK"} <= outcomes)
        for e in self.bench.audit.events:
            self.assertTrue(e["correlation_id"])
        rb = self.bench.audit.find(outcome="ROLLED_BACK")[0]
        self.assertEqual((rb["correlation_id"], rb["ecu_id"], rb["failed_version"]),
                         (cid, "ECU-A", 3))

    def test_ACC_05_signed_manifest_lists_every_ecu(self):
        """ACC-05 | FR-08 SR-13 | UC-05"""
        self.bench.install("ECU-A", 2)
        env = self.gw.build_manifest()
        reason, payload = verify_manifest(env, {self.bench.vehicle_key.key_id: self.bench.vehicle_key.public})
        self.assertIsNone(reason)
        by_id = {e["ecu_id"]: e for e in payload["ecus"]}
        self.assertEqual(set(by_id), {"ECU-A", "ECU-B"})
        self.assertEqual(by_id["ECU-A"]["active_version"], 2)
        self.assertEqual(by_id["ECU-A"]["active_slot"], "B")
        self.assertEqual(by_id["ECU-B"]["active_version"], 1)
        self.assertEqual(by_id["ECU-A"]["hardware_id"], "HW-A-REV2")

    def test_ACC_06_health_confirmation_commits_new_version(self):
        """ACC-06 | FR-09 | UC-08"""
        self.assertTrue(self.bench.update("ECU-A", 2).ok)
        self.assertTrue(self.gw.activate("ECU-A", SAFE, "c1").ok)
        self.assertIs(self.ecu_a.update_state, UpdateState.INSTALLED)
        self.assertEqual(self.ecu_a.boot("c1"), "B")
        self.assertTrue(self.ecu_a.confirm_health(True, "c1").ok)
        self.assertIs(self.ecu_a.update_state, UpdateState.CONFIRMED)
        self.assertEqual((self.ecu_a.active_slot, self.ecu_a.confirmed_slot), ("B", "B"))
        self.assertEqual(self.ecu_a.trusted_min_version, 2)

    def test_ACC_07_failed_health_restores_previous_confirmed_version(self):
        """ACC-07 | FR-10 | UC-09"""
        self.assertTrue(self.bench.update("ECU-A", 2).ok)
        self.assertTrue(self.gw.activate("ECU-A", SAFE, "c1").ok)
        result = self.ecu_a.confirm_health(False, "c1")
        self.assertIs(result.reason, Reason.HEALTH_FAILED)
        self.assertIs(self.ecu_a.update_state, UpdateState.ROLLED_BACK)
        self.assertEqual((self.ecu_a.active_slot, self.ecu_a.active_version), ("A", 1))
        self.assertEqual(self.ecu_a.trusted_min_version, 1)
        self.assertTrue(self.ecu_a.slot_image_valid("A"))

    def test_ACC_08_repeated_instruction_is_idempotent(self):
        """ACC-08 | FR-11 FR-03 | UC-10"""
        env, _ = self.bench.target("ECU-A", 2)
        self.assertIs(self.gw.process_update(env, self.bench.fetch()).reason, Reason.OK)
        before = self.bench.snapshot()
        requests = len(self.bench.repo.requests)
        again = self.gw.process_update(env, self.bench.fetch())
        self.assertTrue(again.ok)
        self.assertIs(again.reason, Reason.ALREADY_APPLIED)
        self.assertEqual(len(self.bench.repo.requests), requests)   # no second download
        self.assertTrustedStateUnchanged(before)

    def test_ACC_09_second_ecu_updates_without_touching_the_first(self):
        """ACC-09 | FR-04 FR-08 | UC-07"""
        a_before = self.ecu_a.snapshot()
        self.bench.install("ECU-B", 5)
        self.assertEqual(self.ecu_a.snapshot(), a_before)
        self.assertEqual((self.ecu_b.active_slot, self.ecu_b.active_version), ("B", 5))
        bundle = {"campaign_id": "CMP-2026-001",
                  "targets": [self.bench.target("ECU-A", 2)[0], self.bench.target("ECU-B", 6)[0]]}
        results = self.gw.process_bundle(bundle, self.bench.fetch())
        self.assertEqual({k: r.reason for k, r in results.items()},
                         {"ECU-A": Reason.OK, "ECU-B": Reason.OK})
        self.assertEqual(self.ecu_b.slot_record("A")["version"], 6)   # ECU-B now stages into A

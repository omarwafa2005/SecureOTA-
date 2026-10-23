"""Fault tests FT-01 .. FT-05 (Section 7 threat catalog, F-01 .. F-05)."""
from vehicle import Reason, SimulatedPowerLoss, UpdateState, VehicleConditions
from vehicle.testkit import SAFE

from .base import BenchTestCase


class FaultTests(BenchTestCase):

    def test_FT_01_network_disconnect_during_download(self):
        """FT-01 | F-01 | FR-03 FR-11 SAF-02"""
        env, _ = self.bench.target("ECU-A", 2)
        before = self.bench.snapshot()
        r = self.gw.process_update(env, self.bench.fetch(disconnect_after=4096))
        self.assertRejected(r, Reason.NETWORK_ERROR)
        self.assertTrustedStateUnchanged(before)
        self.assertRejected(self.gw.activate("ECU-A", SAFE), Reason.INVALID_STATE)  # no partial activation
        retry = self.gw.process_update(env, self.bench.fetch())       # restart from zero
        self.assertIs(retry.reason, Reason.OK)
        self.assertIs(self.ecu_a.update_state, UpdateState.STAGED)

    def test_FT_02_gateway_killed_between_stage_and_bookkeeping(self):
        """FT-02 | F-02 | FR-11"""
        env, _ = self.bench.target("ECU-A", 2)
        self.bench.fail_at.add("gateway:before_record")
        with self.assertRaises(SimulatedPowerLoss):
            self.gw.process_update(env, self.bench.fetch())
        self.restart()
        self.assertIs(self.ecu_a.update_state, UpdateState.STAGED)
        self.assertEqual(self.gw.accepted_metadata_version("ECU-A"), 0)
        r = self.gw.process_update(env, self.bench.fetch())          # retry reconciles
        self.assertTrue(r.ok)
        self.assertIs(r.reason, Reason.ALREADY_APPLIED)
        self.assertEqual(self.gw.accepted_metadata_version("ECU-A"), env["signed"]["metadata_version"])
        self.assertEqual(self.ecu_a.slot_record("B")["version"], 2)

    def test_FT_03_power_loss_during_staging_and_commit(self):
        """FT-03 | F-03 | SAF-06 SAF-08"""
        expectations = {
            "stage:intent_saved": UpdateState.IDLE,
            "stage:mid_write": UpdateState.IDLE,
            "stage:image_synced": UpdateState.IDLE,
            "stage:image_renamed": UpdateState.IDLE,
            "stage:committed": UpdateState.STAGED,
            "activate:before_commit": UpdateState.STAGED,
            "activate:committed": UpdateState.INSTALLED,
        }
        for point, expected in expectations.items():
            with self.subTest(point=point):
                self.setUp()
                self.bench.fail_at.add(point)
                with self.assertRaises(SimulatedPowerLoss):
                    self.bench.update("ECU-A", 2)
                    self.gw.activate("ECU-A", SAFE, "c")
                self.restart()
                self.assertIs(self.ecu_a.update_state, expected)
                self.assertTrue(self.ecu_a.slot_image_valid(self.ecu_a.confirmed_slot))
                self.assertEqual(self.ecu_a.confirmed_slot, "A")
                if expected is UpdateState.IDLE:
                    self.assertIsNone(self.ecu_a.slot_record("B"))
                    self.assertFalse(self.ecu_a.slot_path("B").exists())
                    self.assertEqual(len(self.bench.audit.find(outcome="DISCARDED_PARTIAL_STAGING")), 1)

    def test_FT_03b_interrupted_rollback_completes_on_restart(self):
        """FT-03 | F-03 | SAF-05 SAF-06  (UC-09 exceptional flow: interrupted rollback)"""
        self.assertTrue(self.bench.update("ECU-A", 2).ok)
        self.assertTrue(self.gw.activate("ECU-A", SAFE, "c").ok)
        self.bench.fail_at.add("rollback:before_commit")
        with self.assertRaises(SimulatedPowerLoss):
            self.ecu_a.confirm_health(False, "c")
        self.restart()
        self.assertIs(self.ecu_a.update_state, UpdateState.INSTALLED)   # rollback not yet durable
        slot = None
        for _ in range(self.ecu_a.max_boot_attempts + 1):                # no confirmation arrives
            slot = self.ecu_a.boot()
        self.assertEqual(slot, "A")
        self.assertIs(self.ecu_a.update_state, UpdateState.ROLLED_BACK)

    def test_FT_04_unhealthy_image_rolls_back(self):
        """FT-04 | F-04 | SAF-05 FR-10"""
        self.assertTrue(self.bench.update("ECU-A", 2).ok)
        self.assertTrue(self.gw.activate("ECU-A", SAFE, "c").ok)
        self.assertEqual(self.ecu_a.boot("c"), "B")
        self.ecu_a.confirm_health(False, "c")
        self.assertEqual((self.ecu_a.active_slot, self.ecu_a.confirmed_slot), ("A", "A"))
        self.assertEqual(self.ecu_a.active_version, 1)
        self.assertEqual(self.ecu_a.boot(), "A")
        manifest = self.gw.build_manifest()["signed"]["ecus"]
        self.assertEqual(manifest[0]["update_state"], "ROLLED_BACK")

    def test_FT_05_vehicle_moves_before_activation(self):
        """FT-05 | F-05 | SAF-03 SAF-04"""
        self.assertTrue(self.bench.update("ECU-A", 2).ok)
        moving = VehicleConditions(speed_kph=42.0, gear="D")
        r = self.gw.activate("ECU-A", moving, "c-move")
        self.assertIs(r.reason, Reason.ACTIVATION_POSTPONED)
        self.assertEqual(set(r.detail), {"SPEED_NONZERO", "NOT_IN_PARK"})
        self.assertIs(self.ecu_a.update_state, UpdateState.STAGED)
        self.assertEqual(self.ecu_a.active_slot, "A")
        event = self.bench.audit.find(correlation_id="c-move", outcome="POSTPONED")
        self.assertEqual(len(event), 1)                       # recorded, evidence kept
        self.assertTrue(self.gw.activate("ECU-A", SAFE, "c-park").ok)
        self.assertEqual(self.ecu_a.active_slot, "B")

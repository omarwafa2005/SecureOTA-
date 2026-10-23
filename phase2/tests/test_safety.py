"""Safety and resilience acceptance tests (SAF-01 .. SAF-06)."""
from vehicle import CHECKPOINTS, Reason, SafetyPolicy, SimulatedPowerLoss, UpdateState, VehicleConditions
from vehicle.ecu import sha256_hex
from vehicle.testkit import SAFE

from .base import BenchTestCase


class SafetyTests(BenchTestCase):

    def test_ACC_10_new_firmware_written_only_to_inactive_slot(self):
        """ACC-10 | SAF-01 | UC-07"""
        for version, expected_slot in ((2, "B"), (3, "A"), (4, "B")):
            with self.subTest(version=version):
                active = self.ecu_a.active_slot
                active_bytes = self.ecu_a.slot_path(active).read_bytes()
                self.assertTrue(self.bench.update("ECU-A", version).ok)
                self.assertEqual(self.ecu_a.slot_record(expected_slot)["version"], version)
                self.assertEqual(self.ecu_a.slot_path(active).read_bytes(), active_bytes)
                self.assertTrue(self.gw.activate("ECU-A", SAFE, f"c{version}").ok)
                self.ecu_a.boot()
                self.assertTrue(self.ecu_a.confirm_health(True, f"c{version}").ok)

    def test_ACC_11_active_image_survives_failed_staging(self):
        """ACC-11 | SAF-02 | UC-07"""
        good_a = sha256_hex(self.ecu_a.slot_path("A").read_bytes())
        for point in ("stage:intent_saved", "stage:mid_write", "stage:image_synced"):
            with self.subTest(point=point):
                self.bench.fail_at.add(point)
                with self.assertRaises(SimulatedPowerLoss):
                    self.bench.update("ECU-A", 2)
                self.restart()
                self.assertEqual(sha256_hex(self.ecu_a.slot_path("A").read_bytes()), good_a)
                self.assertEqual(self.ecu_a.active_slot, "A")
                self.assertIs(self.ecu_a.update_state, UpdateState.IDLE)

    def test_ACC_12_activation_blocked_while_moving(self):
        """ACC-12 | SAF-03 | UC-08"""
        self.assertTrue(self.bench.update("ECU-A", 2).ok)
        for speed in (0.1, 5, 130.0):
            r = self.gw.activate("ECU-A", VehicleConditions(speed_kph=speed))
            self.assertIs(r.reason, Reason.ACTIVATION_POSTPONED)
            self.assertIn("SPEED_NONZERO", r.detail)
            self.assertEqual(r.public()["status"], "POSTPONED")
            self.assertEqual(self.ecu_a.active_slot, "A")
        self.assertTrue(self.gw.activate("ECU-A", VehicleConditions(speed_kph=0)).ok)

    def test_ACC_13_activation_postponed_on_low_battery(self):
        """ACC-13 | SAF-04 | UC-08"""
        self.assertTrue(self.bench.update("ECU-A", 2).ok)
        threshold = SafetyPolicy().min_battery_v
        r = self.gw.activate("ECU-A", VehicleConditions(battery_v=threshold - 0.01))
        self.assertIs(r.reason, Reason.ACTIVATION_POSTPONED)
        self.assertEqual(r.detail, ("BATTERY_LOW",))
        self.assertIs(self.ecu_a.update_state, UpdateState.STAGED)
        self.assertTrue(self.gw.activate("ECU-A", VehicleConditions(battery_v=threshold)).ok)

    def test_ACC_13b_battery_threshold_is_configurable(self):
        """ACC-13 | SAF-04"""
        from vehicle import Ecu
        self.assertTrue(self.bench.update("ECU-A", 2).ok)
        ecu = Ecu(self.ecu_a.root, policy=SafetyPolicy(min_battery_v=12.5))
        self.assertIs(ecu.activate(VehicleConditions(battery_v=12.4), "c").reason,
                      Reason.ACTIVATION_POSTPONED)

    def test_ACC_14_rollback_on_failed_or_missing_health(self):
        """ACC-14 | SAF-05 | UC-09"""
        # explicit failure
        self.assertTrue(self.bench.update("ECU-A", 2).ok)
        self.assertTrue(self.gw.activate("ECU-A", SAFE, "c1").ok)
        self.ecu_a.confirm_health(False, "c1")
        self.assertEqual(self.ecu_a.active_slot, "A")
        # watchdog timeout
        self.assertTrue(self.bench.update("ECU-A", 3).ok)
        self.assertTrue(self.gw.activate("ECU-A", SAFE, "c2").ok)
        self.assertFalse(self.ecu_a.watchdog(self.ecu_a.health_timeout_s - 1, "c2"))
        self.assertTrue(self.ecu_a.watchdog(self.ecu_a.health_timeout_s, "c2"))
        self.assertEqual(self.ecu_a.active_slot, "A")
        # boot loop: too many unconfirmed boots
        self.assertTrue(self.bench.update("ECU-A", 4).ok)
        self.assertTrue(self.gw.activate("ECU-A", SAFE, "c3").ok)
        slots = [self.ecu_a.boot("c3") for _ in range(self.ecu_a.max_boot_attempts + 1)]
        self.assertEqual(slots[:-1], ["B"] * self.ecu_a.max_boot_attempts)
        self.assertEqual(slots[-1], "A")
        causes = [e["cause"] for e in self.bench.audit.find(outcome="ROLLED_BACK")]
        self.assertEqual(causes, ["HEALTH_CHECK_FAILED", "HEALTH_TIMEOUT", "BOOT_ATTEMPTS_EXCEEDED"])
        self.assertEqual(self.ecu_a.trusted_min_version, 1)

    def test_ACC_15_any_interruption_leaves_a_bootable_version(self):
        """ACC-15 | SAF-06 SAF-08 | UC-09 UC-10"""
        for point in CHECKPOINTS:
            with self.subTest(point=point):
                self.setUp()                       # fresh bench per checkpoint
                self.bench.fail_at.add(point)
                try:
                    self.bench.install("ECU-A", 2)
                    # rollback checkpoints only occur on the failure path
                    self.bench.update("ECU-A", 3)
                    self.gw.activate("ECU-A", SAFE, "c")
                    self.ecu_a.confirm_health(False, "c")
                except SimulatedPowerLoss:
                    pass
                self.assertIn(point, self.bench.checkpoints_hit, "checkpoint never reached")
                self.restart()
                ecu = self.ecu_a
                ecu.boot()
                self.assertTrue(ecu.slot_image_valid(ecu.active_slot),
                                f"active slot not bootable after power loss at {point}")
                self.assertTrue(ecu.slot_image_valid(ecu.confirmed_slot))
                self.assertNotEqual(ecu.update_state, UpdateState.STAGING)
                self.assertEqual(list(ecu.root.glob("*.tmp")), [])

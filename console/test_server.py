"""Console server tests: the UI flows work end to end over HTTP.

Run from the repository root:  python -m unittest discover -s console -v
"""
from __future__ import annotations

import unittest

from fastapi.testclient import TestClient

from server import VEHICLE_ID, build_app


class ConsoleTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(build_app(dist=None), raise_server_exceptions=False)
        session = self.client.get("/demo/session").json()
        self.tokens = {i["key"]: i["token"] for i in session["identities"]}

    def as_(self, who):
        return {"Authorization": f"Bearer {self.tokens[who]}"}

    def ecu_a(self):
        ecus = self.client.get("/demo/vehicle").json()["ecus"]
        return next(e for e in ecus if e["ecu_id"] == "ECU-A")

    def release_and_campaign(self, version=2):
        c = self.client
        image = c.get("/demo/firmware", params={"ecu_id": "ECU-A", "version": version}).content
        art = c.post("/api/artifacts", params={"ecu_id": "ECU-A", "hardware_id": "HW-A-REV2"},
                     content=image, headers=self.as_("creator"))
        self.assertEqual(art.status_code, 201, art.text)
        rel = c.post("/api/releases", json={"artifact_id": art.json()["artifact_id"],
                                            "version": version}, headers=self.as_("creator"))
        rid = rel.json()["release_id"]
        self.assertEqual(c.post(f"/api/releases/{rid}/approve",
                                headers=self.as_("approver")).status_code, 200)
        cmp_ = c.post("/api/campaigns", headers=self.as_("operator"), json={
            "release_ids": [rid], "targets": [VEHICLE_ID],
            "policy": {"expires_in_s": 3600, "require_safe_state": True}})
        cmp_id = cmp_.json()["campaign_id"]
        self.assertEqual(c.post(f"/api/campaigns/{cmp_id}/start",
                                headers=self.as_("operator")).status_code, 200)
        return cmp_id

    def status(self, cmp_id):
        rows = self.client.get(f"/api/campaigns/{cmp_id}/status",
                               headers=self.as_("operator")).json()["assignments"]
        return {r["ecu_id"]: r["state"] for r in rows}

    def test_session_lists_staff_identities_only(self):
        session = self.client.get("/demo/session").json()
        self.assertEqual(session["vehicle_id"], VEHICLE_ID)
        self.assertTrue(all("vehicle" not in i["roles"] for i in session["identities"]))

    def test_full_update_reaches_confirmed(self):
        cmp_id = self.release_and_campaign()
        c = self.client
        poll = c.post("/demo/vehicle/poll", json={}).json()
        self.assertEqual([(r["ecu_id"], r["status"]) for r in poll["results"]], [("ECU-A", "OK")])
        self.assertEqual(self.ecu_a()["update_state"], "STAGED")
        self.assertEqual(c.post("/demo/vehicle/activate",
                                json={"ecu_id": "ECU-A"}).json()["status"], "OK")
        c.post("/demo/vehicle/boot", json={"ecu_id": "ECU-A"})
        self.assertEqual(c.post("/demo/vehicle/confirm",
                                json={"ecu_id": "ECU-A", "healthy": True}).json()["status"], "OK")
        ecu = self.ecu_a()
        self.assertEqual((ecu["active_slot"], ecu["active_version"], ecu["update_state"]),
                         ("B", 2, "CONFIRMED"))
        self.assertEqual(self.status(cmp_id), {"ECU-A": "CONFIRMED"})
        catalog = c.get("/demo/catalog", headers=self.as_("auditor")).json()
        vehicle = next(v for v in catalog["vehicles"] if v["vehicle_id"] == VEHICLE_ID)
        self.assertEqual(vehicle["ecus"][0]["active_version"], 2)           # manifest synced

    def test_activation_postponed_while_moving(self):
        self.release_and_campaign()
        self.client.post("/demo/vehicle/poll", json={})
        r = self.client.post("/demo/vehicle/activate", json={
            "ecu_id": "ECU-A", "conditions": {"speed_kph": 42, "gear": "D"}}).json()
        self.assertEqual(r["status"], "POSTPONED")
        self.assertIn("SPEED_NONZERO", r["blockers"])
        self.assertEqual(self.ecu_a()["active_slot"], "A")

    def test_unhealthy_image_rolls_back(self):
        cmp_id = self.release_and_campaign()
        c = self.client
        c.post("/demo/vehicle/poll", json={})
        c.post("/demo/vehicle/activate", json={"ecu_id": "ECU-A"})
        r = c.post("/demo/vehicle/confirm", json={"ecu_id": "ECU-A", "healthy": False}).json()
        self.assertEqual(r["reason"], "HEALTH_FAILED")
        ecu = self.ecu_a()
        self.assertEqual((ecu["active_slot"], ecu["active_version"]), ("A", 1))
        self.assertEqual(self.status(cmp_id), {"ECU-A": "ROLLED_BACK"})

    def test_attacks_are_rejected(self):
        for attack, reason in (("tamper", "DIGEST_MISMATCH"), ("forge", "BAD_SIGNATURE")):
            with self.subTest(attack=attack):
                self.client.post("/demo/reset")
                self.setUp()
                cmp_id = self.release_and_campaign()
                r = self.client.post("/demo/vehicle/poll", json={"attack": attack}).json()
                self.assertEqual([(x["status"], x["reason"]) for x in r["results"]],
                                 [("REJECTED", reason)])
                ecu = self.ecu_a()
                self.assertEqual((ecu["active_slot"], ecu["active_version"], ecu["slots"]["B"]),
                                 ("A", 1, None))
                self.assertEqual(self.status(cmp_id), {"ECU-A": "REJECTED"})

    def test_power_loss_during_staging_recovers_and_retries(self):
        self.release_and_campaign()
        r = self.client.post("/demo/vehicle/poll", json={"attack": "power_loss"}).json()
        self.assertEqual(r["results"][0]["status"], "POWER_LOSS")
        ecu = self.ecu_a()
        self.assertEqual((ecu["active_slot"], ecu["update_state"], ecu["slots"]["B"]),
                         ("A", "IDLE", None))
        retry = self.client.post("/demo/vehicle/poll", json={}).json()
        self.assertEqual(retry["results"][0]["status"], "OK")

    def test_catalog_needs_an_oem_identity(self):
        self.assertEqual(self.client.get("/demo/catalog").status_code, 401)
        r = self.client.get("/demo/catalog", headers=self.as_("registrar"))
        self.assertEqual(r.status_code, 200)
        self.assertNotIn("token", r.text)
        audit = self.client.get("/api/audit", params={"action": "view_catalog"},
                                headers=self.as_("auditor")).json()
        self.assertEqual([e["outcome"] for e in audit["events"]], ["UNAUTHENTICATED", "SUCCESS"])


if __name__ == "__main__":
    unittest.main()

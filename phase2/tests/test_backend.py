"""Backend acceptance and negative tests (Student 2).

Docstring format: <test ID> | <threat IDs or -> | <requirement IDs>.
"""
from fastapi.testclient import TestClient

from oem_backend import ApiError, AuditTrail, dependency_order
from oem_backend.api import create_app
from vehicle.testkit import ECU_HW, VEHICLE_ID, firmware

from .fleet import OTHER_VEHICLE, FleetTestCase

ORDINARY = {"expires_in_s": 3600, "require_safe_state": True}


class BackendTests(FleetTestCase):

    def assertApiError(self, category, code, fn, *args):
        with self.assertRaises(ApiError) as ctx:
            fn(*args)
        self.assertEqual((ctx.exception.category, ctx.exception.code), (category, code))
        return ctx.exception

    def http(self):
        return TestClient(create_app(self.backend, self.fleet.auth),
                          raise_server_exceptions=False)

    def bearer(self, who):
        return {"Authorization": f"Bearer {self.fleet.tokens[who]}"}

    # ------------------------------------------------------------ functional
    def test_ACC_20_register_vehicle_and_ecus(self):
        """ACC-20 | - | FR-01"""
        reg = self.p["registrar"]
        body = {"vehicle_id": "VIN-SIM-0100", "manifest_key_id": "vk-0100",
                "manifest_public_key": "ab" * 32,
                "ecus": [{"ecu_id": "ECU-A", "hardware_id": "HW-A-REV2"},
                         {"ecu_id": "ECU-B", "hardware_id": "HW-B-REV1"}]}
        self.assertEqual(self.backend.register_vehicle(reg, body, "cid-acc20-1"),
                         {"vehicle_id": "VIN-SIM-0100", "ecus": ["ECU-A", "ECU-B"]})
        self.assertApiError("CONFLICT", "DUPLICATE_VEHICLE",
                            self.backend.register_vehicle, reg, body, "cid-acc20-2")
        bad = dict(body, vehicle_id="vin with spaces")
        self.assertApiError("VALIDATION_FAILED", "INVALID_IDENTITY",
                            self.backend.register_vehicle, reg, bad, "cid-acc20-3")
        dup_ecu = dict(body, vehicle_id="VIN-SIM-0101",
                       ecus=[{"ecu_id": "ECU-A", "hardware_id": "HW-1"}] * 2)
        self.assertApiError("CONFLICT", "DUPLICATE_ECU",
                            self.backend.register_vehicle, reg, dup_ecu, "cid-acc20-4")
        self.assertNotIn("VIN-SIM-0101", self.backend._db["vehicles"])   # transaction rolled back

    def test_ACC_21_instructions_only_for_eligible_ecus(self):
        """ACC-21 | - | FR-02 FR-16"""
        rid = self.fleet.release("ECU-A", 2)
        cmp_id = self.fleet.campaign([rid], targets=[VEHICLE_ID])
        veh = self.p["vehicle"]
        first = self.backend.get_instructions(veh, VEHICLE_ID, "cid-acc21-1")
        targets = first["bundles"][0]["targets"]
        self.assertEqual([t["signed"]["ecu_id"] for t in targets], ["ECU-A"])
        self.assertEqual(targets[0]["signed"]["vehicle_id"], VEHICLE_ID)
        self.assertEqual(targets[0]["key_id"], "release-key-1")
        # a repeated poll returns the identical signed offer (gateway treats it as ALREADY_APPLIED)
        again = self.backend.get_instructions(veh, VEHICLE_ID, "cid-acc21-2")
        self.assertEqual(again["bundles"][0]["targets"], targets)
        # other vehicle has incompatible hardware and is not targeted -> nothing
        other = self.backend.get_instructions(self.p["other_vehicle"], OTHER_VEHICLE, "cid-acc21-3")
        self.assertEqual(other["bundles"], [])
        # paused campaign offers nothing new
        self.backend.pause_campaign(self.p["operator"], cmp_id, "cid-acc21-4")
        self.assertEqual(self.backend.get_instructions(veh, VEHICLE_ID, "cid-acc21-5")["bundles"], [])
        self.backend.start_campaign(self.p["operator"], cmp_id, "cid-acc21-6")
        self.assertEqual(len(self.backend.get_instructions(veh, VEHICLE_ID, "cid-acc21-7")["bundles"]), 1)
        # a vehicle identity cannot ask for any other vehicle id (checked before lookup)
        self.assertApiError("FORBIDDEN", "FORBIDDEN", self.backend.get_instructions,
                            veh, "VIN-UNKNOWN-1", "cid-acc21-8")

    def test_ACC_22_campaign_requires_explicit_targets_and_policy(self):
        """ACC-22 | T-05 | FR-07"""
        rid = self.fleet.release("ECU-A", 2)
        op = self.p["operator"]
        ok = self.backend.create_campaign(op, {"release_ids": [rid], "targets": [VEHICLE_ID],
                                               "policy": ORDINARY}, "cid-acc22-1")
        self.assertEqual(ok["state"], "DRAFT")
        cases = [
            ({"release_ids": [rid], "targets": [], "policy": ORDINARY}, "INVALID_TARGETS"),
            ({"release_ids": [rid], "targets": ["VIN-NOPE-9"], "policy": ORDINARY}, "UNKNOWN_TARGET"),
            ({"release_ids": [rid], "targets": [OTHER_VEHICLE], "policy": ORDINARY},
             "INCOMPATIBLE_TARGET"),
            ({"release_ids": [rid], "targets": [VEHICLE_ID],
              "policy": {"expires_in_s": 3600, "require_safe_state": False}}, "INVALID_POLICY"),
            ({"release_ids": [rid], "targets": [VEHICLE_ID],
              "policy": {"expires_in_s": 10, "require_safe_state": True}}, "INVALID_POLICY"),
            ({"release_ids": [rid], "targets": [VEHICLE_ID]}, "MISSING_FIELD"),
        ]
        for body, code in cases:
            with self.subTest(code=code):
                self.assertApiError("VALIDATION_FAILED", code, self.backend.create_campaign,
                                    op, body, "cid-acc22-x")
        self.assertEqual(len(self.backend._db["campaigns"]), 1)

    def test_ACC_23_event_reports_drive_assignment_state(self):
        """ACC-23 | - | FR-12"""
        rid = self.fleet.release("ECU-A", 2)
        cmp_id = self.fleet.campaign([rid])
        env = self.backend.get_instructions(self.p["vehicle"], VEHICLE_ID, "cid-acc23-1")[
            "bundles"][0]["targets"][0]
        mv = env["signed"]["metadata_version"]
        for outcome, expected in (("STAGED", "STAGED"), ("POSTPONED", "STAGED"),
                                  ("INSTALLED", "INSTALLED"), ("CONFIRMED", "CONFIRMED")):
            r = self.fleet.report(cmp_id, "ECU-A", outcome, mv, "cid-acc23-2")
            self.assertEqual(r["assignment_state"], expected)
        self.assertApiError("CONFLICT", "INVALID_TRANSITION", self.fleet.report,
                            cmp_id, "ECU-A", "ROLLED_BACK", mv, "cid-acc23-3")

    def test_ACC_24_upload_publishes_sha256_and_length(self):
        """ACC-24 | T-01 | SR-01"""
        import hashlib
        image = firmware("ECU-A", 7)
        art = self.backend.upload_artifact(self.p["creator"], image, "ECU-A", ECU_HW["ECU-A"],
                                           "cid-acc24-1")
        self.assertEqual(art["sha256"], hashlib.sha256(image).hexdigest())
        self.assertEqual(art["length"], len(image))
        rid = self.backend.create_release(self.p["creator"], {"artifact_id": art["artifact_id"],
                                                              "version": 7}, "cid-acc24-2")
        rel = self.backend._db["releases"][rid["release_id"]]
        self.assertEqual((rel["sha256"], rel["length"]), (art["sha256"], art["length"]))
        self.assertApiError("VALIDATION_FAILED", "EMPTY_ARTIFACT", self.backend.upload_artifact,
                            self.p["creator"], b"", "ECU-A", "HW-A-REV2", "cid-acc24-3")

    def test_ACC_25_release_needs_a_different_approver(self):
        """ACC-25 | T-10 | SR-18"""
        both = self.p["both"]
        art = self.backend.upload_artifact(both, firmware("ECU-A", 3), "ECU-A", "HW-A-REV2", "c-acc25-1")
        rid = self.backend.create_release(both, {"artifact_id": art["artifact_id"], "version": 3},
                                          "c-acc25-2")["release_id"]
        self.assertApiError("FORBIDDEN", "SEPARATION_OF_DUTIES",
                            self.backend.approve_release, both, rid, "c-acc25-3")
        self.assertEqual(self.backend._db["releases"][rid]["state"], "DRAFT")
        # an unapproved release cannot enter a campaign
        self.assertApiError("CONFLICT", "RELEASE_NOT_APPROVED", self.backend.create_campaign,
                            self.p["operator"], {"release_ids": [rid], "targets": [VEHICLE_ID],
                                                 "policy": ORDINARY}, "c-acc25-4")
        self.backend.approve_release(self.p["approver"], rid, "c-acc25-5")
        self.assertEqual(self.backend._db["releases"][rid]["approved_by"], "carol.approver")

    def test_ACC_26_every_privileged_operation_is_audited(self):
        """ACC-26 | T-10 | SR-09"""
        before = len(self.backend.audit.events)
        rid = self.fleet.release("ECU-A", 2, cid="cid-acc26-1")
        self.fleet.campaign([rid], cid="cid-acc26-2")
        events = self.backend.audit.events[before:]
        self.assertEqual([e["action"] for e in events],
                         ["upload_artifact", "create_release", "approve_release",
                          "create_campaign", "start_campaign"])
        for e in events:
            for field in ("actor", "action", "object", "outcome", "time", "correlation_id"):
                self.assertTrue(e[field], f"{field} missing in {e}")
            self.assertEqual(e["outcome"], "SUCCESS")

    def test_ACC_27_audit_chain_verifies(self):
        """ACC-27 | B-05 | SR-14"""
        self.fleet.release("ECU-A", 2)
        anchor = self.backend.audit.head()
        self.assertEqual(self.backend.audit.verify(anchor), (True, None))
        res = self.backend.query_audit(self.p["auditor"], "cid-acc27-1")
        self.assertTrue(res["chain_intact"])

    def test_ACC_28_operator_view_distinguishes_update_states(self):
        """ACC-28 | - | US-01"""
        ra, rb = self.fleet.release("ECU-A", 2), self.fleet.release("ECU-B", 2, cid="rel-00002")
        cmp_id = self.fleet.campaign([ra, rb])
        bundle = self.backend.get_instructions(self.p["vehicle"], VEHICLE_ID, "c-acc28-1")["bundles"][0]
        mv = {t["signed"]["ecu_id"]: t["signed"]["metadata_version"] for t in bundle["targets"]}
        for o in ("STAGED", "INSTALLED", "ROLLED_BACK"):
            self.fleet.report(cmp_id, "ECU-A", o, mv["ECU-A"], "c-acc28-2")
        self.fleet.report(cmp_id, "ECU-B", "STAGED", mv["ECU-B"], "c-acc28-3")
        status = self.backend.campaign_status(self.p["operator"], cmp_id, "c-acc28-4")
        labels = {a["ecu_id"]: a["label"] for a in status["assignments"]}
        self.assertEqual(labels, {"ECU-A": "Rolled back to previous version",
                                  "ECU-B": "Staged (inactive slot)"})
        from oem_backend import STATUS_LABELS
        self.assertEqual(len(set(STATUS_LABELS.values())), len(STATUS_LABELS))  # all distinct

    def test_ACC_29_correlation_id_is_carried_end_to_end(self):
        """ACC-29 | - | NFR-02"""
        rid = self.fleet.release("ECU-A", 2)
        self.fleet.campaign([rid])
        cid = "corr-acc29-0001"
        self.fleet.poll_and_stage(cid)
        backend_actions = {e["action"] for e in self.backend.audit.query(correlation_id=cid)}
        self.assertTrue({"get_instructions", "download_artifact", "report_event"} <= backend_actions)
        vehicle_events = self.fleet.bench.audit.find(correlation_id=cid)
        self.assertTrue({"gateway", "ecu"} <= {e["component"] for e in vehicle_events})
        with self.http() as client:
            r = client.get("/health", headers={"X-Correlation-ID": "corr-http-0001"})
            self.assertEqual(r.headers["X-Correlation-ID"], "corr-http-0001")
            r = client.get("/health")
            self.assertRegex(r.json()["correlation_id"], r"^[0-9a-f]{32}$")

    def test_ACC_31_registration_rejects_personal_data(self):
        """ACC-31 | - | PR-01"""
        body = {"vehicle_id": "VIN-SIM-0200", "manifest_key_id": "vk", "manifest_public_key": "cd" * 32,
                "ecus": [{"ecu_id": "ECU-A", "hardware_id": "HW-A-REV2"}]}
        for extra in ({"owner_name": "Jane Doe"}, {"gps_position": "52.1,4.3"}, {"phone": "+31"}):
            with self.subTest(extra=extra):
                self.assertApiError("VALIDATION_FAILED", "UNEXPECTED_FIELD",
                                    self.backend.register_vehicle, self.p["registrar"],
                                    {**body, **extra}, "cid-acc31-1")
        stored = self.backend.register_vehicle(self.p["registrar"], body, "cid-acc31-2")
        record = self.backend._db["vehicles"][stored["vehicle_id"]]
        self.assertEqual(set(record), {"vehicle_id", "ecus", "manifest_key_id",
                                       "manifest_public_key", "last_manifest_at"})

    # -------------------------------------------------------------- negative
    def test_AT_10_unauthorized_privileged_actions_denied_and_audited(self):
        """AT-10 | T-10 B-02 | SR-08 SR-09"""
        rid = self.fleet.release("ECU-A", 2)
        attempts = [
            ("operator", "approve_release", lambda p: self.backend.approve_release(p, rid, "c-at10-1")),
            ("creator", "create_campaign", lambda p: self.backend.create_campaign(
                p, {"release_ids": [rid], "targets": [VEHICLE_ID], "policy": ORDINARY}, "c-at10-2")),
            ("vehicle", "upload_artifact", lambda p: self.backend.upload_artifact(
                p, b"x", "ECU-A", "HW-A-REV2", "c-at10-3")),
            ("approver", "register_vehicle", lambda p: self.backend.register_vehicle(p, {}, "c-at10-4")),
        ]
        for who, action, call in attempts:
            with self.subTest(who=who, action=action):
                before = len(self.backend.audit.events)
                with self.assertRaises(ApiError) as ctx:
                    call(self.p[who])
                self.assertEqual(ctx.exception.category, "FORBIDDEN")
                new = self.backend.audit.events[before:]
                self.assertEqual([(e["actor"], e["action"], e["outcome"]) for e in new],
                                 [(self.p[who].name, action, "DENIED")])
        self.assertEqual(len(self.backend._db["campaigns"]), 0)

    def test_AT_12_dependency_cycle_rejected_with_diagnostic(self):
        """AT-12 | T-12 | FR-14"""
        ra, rb = self.fleet.release("ECU-A", 2), self.fleet.release("ECU-B", 2, cid="rel-00002")
        err = self.assertApiError(
            "VALIDATION_FAILED", "DEPENDENCY_CYCLE", self.backend.create_campaign,
            self.p["operator"], {"release_ids": [ra, rb], "targets": [VEHICLE_ID], "policy": ORDINARY,
                                 "dependencies": {"ECU-A": ["ECU-B"], "ECU-B": ["ECU-A"]}}, "c-at12-1")
        self.assertEqual(err.diagnostic, "ECU-A -> ECU-B -> ECU-A")
        self.assertEqual(dependency_order(["ECU-A", "ECU-B"], {"ECU-A": ["ECU-B"]}),
                         ["ECU-B", "ECU-A"])
        ok = self.backend.create_campaign(self.p["operator"], {
            "release_ids": [ra, rb], "targets": [VEHICLE_ID], "policy": ORDINARY,
            "dependencies": {"ECU-A": ["ECU-B"]}}, "c-at12-2")
        self.assertEqual(ok["ecu_order"], ["ECU-B", "ECU-A"])

    def test_AT_20_unauthenticated_and_forged_tokens_rejected(self):
        """AT-20 | B-01 | SR-08"""
        with self.http() as client:
            for headers in ({}, {"Authorization": "Bearer " + "x" * 43},
                            {"Authorization": self.fleet.tokens["operator"]}):   # missing scheme
                with self.subTest(headers=list(headers)):
                    r = client.post("/campaigns", json={}, headers=headers)
                    self.assertEqual(r.status_code, 401)
                    self.assertEqual(r.json()["error"], "UNAUTHENTICATED")
        unauth = self.backend.audit.query(outcome="UNAUTHENTICATED")
        self.assertEqual(len(unauth), 3)
        self.assertTrue(all(e["actor"] == "anonymous" for e in unauth))

    def test_AT_21_errors_reveal_no_paths_or_secrets(self):
        """AT-21 | B-07 | SR-11 US-02"""
        def boom(*_a, **_k):
            raise RuntimeError(r"C:\secret\keys\release-key-1.pem: password=hunter2")
        self.backend.campaign_status = boom
        with self.http() as client:
            r = client.get("/campaigns/CMP-0001/status", headers=self.bearer("operator"))
            self.assertEqual(r.status_code, 500)
            self.assertEqual(set(r.json()), {"error", "code", "message", "correlation_id"})
            for leak in ("secret", "pem", "hunter2", "Traceback", "\\", "/"):
                self.assertNotIn(leak, r.json()["message"] + r.json()["code"])
            r = client.post("/releases", content=b"{not json", headers=self.bearer("creator"))
            self.assertEqual((r.status_code, r.json()["code"]), (422, "MALFORMED_JSON"))
            r = client.get("/campaigns/CMP-9999/status", headers=self.bearer("auditor"))
            self.assertEqual(set(r.json()), {"error", "code", "message", "correlation_id"})

    def test_AT_22_audit_query_requires_auditor(self):
        """AT-22 | T-10 | SR-08"""
        for who in ("operator", "approver", "vehicle"):
            with self.subTest(who=who):
                self.assertApiError("FORBIDDEN", "FORBIDDEN", self.backend.query_audit,
                                    self.p[who], "c-at22-1")
        self.assertTrue(self.backend.query_audit(self.p["auditor"], "c-at22-2")["chain_intact"])

    def test_AT_28_audit_tampering_is_detected(self):
        """AT-28 | B-05 | SR-14 NFR-05"""
        def trail():
            t = AuditTrail(clock=lambda: 1.0)
            for i in range(5):
                t.record(actor="a", action=f"act{i}", obj="o", outcome="SUCCESS",
                         correlation_id=f"cid-{i}")
            return t
        t = trail()
        t._raw[2]["actor"] = "someone.else"                    # modified event
        self.assertEqual(t.verify(), (False, 3))
        t = trail()
        del t._raw[1]                                          # deleted event
        self.assertEqual(t.verify(), (False, 2))
        t = trail()
        anchor = t.head()
        t._raw.pop()                                           # truncated tail: only the anchor shows it
        self.assertEqual(t.verify(), (True, None))
        self.assertEqual(t.verify(anchor), (False, 4))
        with self.assertRaises(ValueError):                    # secrets never enter the trail
            t.record(actor="a", action="x", obj="o", outcome="SUCCESS", correlation_id="c",
                     api_token="abc")
        # the auditor sees the break through the normal query
        self.fleet.release("ECU-A", 2)
        self.backend.audit._raw[0]["outcome"] = "FAILED"
        res = self.backend.query_audit(self.p["auditor"], "c-at28-1")
        self.assertEqual((res["chain_intact"], res["first_bad_seq"]), (False, 1))

    def test_AT_29_oversized_upload_rejected(self):
        """AT-29 | B-06 | SR-19"""
        self.backend.max_artifact_bytes = 1024
        self.assertApiError("PAYLOAD_TOO_LARGE", "ARTIFACT_TOO_LARGE", self.backend.upload_artifact,
                            self.p["creator"], b"\0" * 1025, "ECU-A", "HW-A-REV2", "c-at29-1")
        with self.http() as client:
            r = client.post("/artifacts?ecu_id=ECU-A&hardware_id=HW-A-REV2", content=b"\0" * 4096,
                            headers=self.bearer("creator"))
            self.assertEqual((r.status_code, r.json()["code"]), (413, "ARTIFACT_TOO_LARGE"))
            r = client.post("/artifacts?ecu_id=ECU-A&hardware_id=HW-A-REV2", content=b"\1" * 1024,
                            headers=self.bearer("creator"))
            self.assertEqual(r.status_code, 201)
        self.assertEqual(len(self.backend._db["artifacts"]), 1)

    def test_AT_30_duplicate_and_stale_event_reports(self):
        """AT-30 | B-08 | FR-13"""
        rid = self.fleet.release("ECU-A", 2)
        cmp_id = self.fleet.campaign([rid])
        mv = self.backend.get_instructions(self.p["vehicle"], VEHICLE_ID, "c-at30-1")[
            "bundles"][0]["targets"][0]["signed"]["metadata_version"]
        body = {"event_id": "evt-at30-0001", "campaign_id": cmp_id, "ecu_id": "ECU-A",
                "outcome": "STAGED", "metadata_version": mv}
        veh = self.p["vehicle"]
        first = self.backend.report_event(veh, VEHICLE_ID, body, "c-at30-2")
        again = self.backend.report_event(veh, VEHICLE_ID, body, "c-at30-3")
        self.assertEqual((first["duplicate"], again["duplicate"]), (False, True))
        self.assertEqual(self.backend._db["assignments"][f"{cmp_id}|{VEHICLE_ID}|ECU-A"]["history"],
                         ["OFFERED", "STAGED"])                               # applied once
        self.assertApiError("CONFLICT", "EVENT_ID_REUSED", self.backend.report_event, veh, VEHICLE_ID,
                            dict(body, outcome="INSTALLED"), "c-at30-4")
        self.assertApiError("CONFLICT", "STALE_EVENT", self.backend.report_event, veh, VEHICLE_ID,
                            dict(body, event_id="evt-at30-0002", outcome="INSTALLED",
                                 metadata_version=mv - 1 if mv > 1 else 99), "c-at30-5")

    def test_AT_31_vehicle_cannot_act_for_another_vehicle(self):
        """AT-31 | B-01 | SR-08"""
        rid = self.fleet.release("ECU-A", 2)
        self.fleet.campaign([rid])
        intruder = self.p["other_vehicle"]
        self.assertApiError("FORBIDDEN", "FORBIDDEN", self.backend.get_instructions,
                            intruder, VEHICLE_ID, "c-at31-1")
        art_id = self.backend._db["releases"][rid]["artifact_id"]
        self.assertApiError("NOT_FOUND", "UNKNOWN_ARTIFACT", self.backend.download_artifact,
                            intruder, art_id, "c-at31-2")
        with self.http() as client:
            r = client.post(f"/vehicles/{VEHICLE_ID}/events", json={},
                            headers=self.bearer("other_vehicle"))
            self.assertEqual(r.status_code, 403)

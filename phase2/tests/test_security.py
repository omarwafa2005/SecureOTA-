"""Key lifecycle, signing-service and secret-handling tests (Student 3).

Docstring format: <test ID> | <threat IDs or -> | <requirement IDs>.
"""
import copy
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from security import KeyLocationError, SigningRefused, SigningService, TrustStore
from security.signing import PASSPHRASE_ENV
from tools import scan_secrets
from vehicle import Reason
from vehicle.metadata import sign_envelope
from vehicle.testkit import VEHICLE_ID

from .fleet import RELEASE_KEY, ROOT_KEY, VEHICLE_KEY, YEAR, FleetTestCase

PHASE2 = Path(__file__).resolve().parent.parent


class KeyLifecycleTests(FleetTestCase):

    def keyset(self, version, include, revoked=(), root=ROOT_KEY, expires_in=YEAR):
        return self.fleet.signer.sign_keyset(version=version,
                                             expires_at=int(self.fleet.clock()) + expires_in,
                                             include=include, revoked=revoked, root_key_id=root)

    def offer(self, ecu_id="ECU-A", version=2):
        rid = self.fleet.release(ecu_id, version, cid=f"rel-{version:05d}")
        self.fleet.campaign([rid], cid=f"cmp-{version:05d}")
        return self.backend.get_instructions(self.p["vehicle"], VEHICLE_ID, "sec-00001")

    def test_ACC_30_release_key_rotation(self):
        """ACC-30 | K-02 | SR-16 SR-17"""
        signer = self.fleet.signer
        signer.generate("release-key-2", "release")
        new = self.keyset(2, {RELEASE_KEY: "release", "release-key-2": "release",
                              VEHICLE_KEY: "vehicle"})
        self.assertIsNone(self.fleet.trust.apply(new))
        self.assertEqual(self.fleet.trust.version, 2)
        self.assertEqual(set(self.fleet.trust.keys_for("release")), {RELEASE_KEY, "release-key-2"})
        # the backend switches to the new key; the vehicle accepts it after the key set update
        self.backend._release_key_id = "release-key-2"
        self.fleet.gateway = self.fleet.make_gateway()
        bundle = self.offer()["bundles"][0]
        self.assertEqual(bundle["targets"][0]["key_id"], "release-key-2")
        results = self.fleet.gateway.process_bundle(
            bundle, self.backend.fetcher(self.p["vehicle"], "sec-00002"), "sec-00002")
        self.assertTrue(results["ECU-A"].ok, results)
        # the trust store survives a restart because it re-verifies its stored key set
        reopened = TrustStore(root_key_id=ROOT_KEY, root_public=signer.public(ROOT_KEY),
                              state_dir=self.fleet.bench.root)
        self.assertEqual(reopened.version, 2)

    def test_AT_24_key_set_rollback_forgery_and_expiry_rejected(self):
        """AT-24 | K-02 | SR-16"""
        signer, trust = self.fleet.signer, self.fleet.trust
        signer.generate("rogue-root", "root")
        signer.generate("evil-release", "release")
        before = (trust.version, set(trust.keys_for("release")))
        cases = {
            "rollback to same version": (self.keyset(1, {"evil-release": "release"}),
                                         Reason.REPLAYED_METADATA),
            "signed by unknown root": (self.keyset(5, {"evil-release": "release"}, root="rogue-root"),
                                       Reason.UNTRUSTED_KEY),
            "expired": (self.keyset(6, {"evil-release": "release"}, expires_in=-1),
                        Reason.EXPIRED_METADATA),
        }
        tampered = self.keyset(7, {RELEASE_KEY: "release"})
        tampered["signed"]["keys"]["evil-release"] = {"role": "release", "public": "00" * 32}
        cases["modified after signing"] = (tampered, Reason.BAD_SIGNATURE)
        root_entry = self.keyset(8, {RELEASE_KEY: "release"})
        unsigned = copy.deepcopy(root_entry["signed"])
        unsigned["keys"]["new-root"] = {"role": "root", "public": "11" * 32}
        cases["adds a root key"] = (sign_envelope(unsigned, signer._keys[ROOT_KEY].private, ROOT_KEY),
                                    Reason.MALFORMED_METADATA)
        for name, (env, reason) in cases.items():
            with self.subTest(name):
                self.assertIs(trust.apply(env), reason)
                self.assertEqual((trust.version, set(trust.keys_for("release"))), before)

    def test_AT_25_compromised_release_key_revoked(self):
        """AT-25 | K-03 T-02 | SR-04 SR-16"""
        signer = self.fleet.signer
        signer.generate("release-key-2", "release")
        stolen_offer = self.offer()["bundles"][0]          # signed with release-key-1
        revocation = self.keyset(2, {"release-key-2": "release", VEHICLE_KEY: "vehicle"},
                                 revoked=[RELEASE_KEY])
        self.assertIsNone(self.fleet.trust.apply(revocation))
        self.assertNotIn(RELEASE_KEY, self.fleet.trust.keys_for("release"))
        self.fleet.gateway = self.fleet.make_gateway()
        before = self.fleet.bench.snapshot()
        r = self.fleet.gateway.process_bundle(
            stolen_offer, self.backend.fetcher(self.p["vehicle"], "sec-at25"), "sec-at25")
        self.assertIs(r["*"].reason, Reason.UNTRUSTED_KEY)
        self.assertEqual(self.fleet.bench.snapshot(), before)

    def test_AT_26_signing_service_refuses_misuse(self):
        """AT-26 | K-01 K-04 | SR-15 SR-17 SR-18"""
        signer = self.fleet.signer
        rid = self.fleet.release("ECU-A", 2)
        release = dict(self.backend._db["releases"][rid])
        payload = {"artifact_id": release["artifact_id"], "campaign_id": "CMP-0001",
                   "vehicle_id": VEHICLE_ID, "ecu_id": "ECU-A", "hardware_id": release["hardware_id"],
                   "version": 2, "metadata_version": 1, "length": release["length"],
                   "sha256": release["sha256"], "expires_at": int(self.fleet.clock()) + 3600}
        cases = [
            ("draft release", dict(release, state="DRAFT"), payload, RELEASE_KEY,
             "RELEASE_NOT_APPROVED"),
            ("self approval", dict(release, approved_by=release["created_by"]), payload,
             RELEASE_KEY, "SEPARATION_OF_DUTIES"),
            ("payload differs", release, dict(payload, version=99), RELEASE_KEY,
             "PAYLOAD_DIFFERS_FROM_RELEASE"),
            ("vehicle key", release, payload, VEHICLE_KEY, "WRONG_KEY_ROLE"),
            ("root key", release, payload, ROOT_KEY, "WRONG_KEY_ROLE"),
            ("unknown key", release, payload, "nope-key", "UNKNOWN_KEY"),
        ]
        for name, rel, pl, key_id, code in cases:
            with self.subTest(name):
                with self.assertRaises(SigningRefused) as ctx:
                    signer.sign_target(pl, rel, key_id)
                self.assertEqual(ctx.exception.code, code)
        refusals = [u["outcome"] for u in signer.usage_log if u["outcome"] != "SIGNED"]
        self.assertEqual(refusals, ["REFUSED_NOT_APPROVED", "REFUSED_SELF_APPROVAL",
                                    "REFUSED_WRONG_ROLE", "REFUSED_WRONG_ROLE"])
        # metadata signed by a non-release key (here the vehicle key) is not trusted by the gateway
        forged = sign_envelope(payload, signer._keys[VEHICLE_KEY].private, VEHICLE_KEY)
        r = self.fleet.gateway.process_update(forged, self.backend.fetcher(self.p["vehicle"], "x" * 8))
        self.assertIs(r.reason, Reason.UNTRUSTED_KEY)


class SecretHandlingTests(unittest.TestCase):

    def test_AT_27_private_keys_never_stored_in_the_source_tree(self):
        """AT-27 | B-09 | SR-10"""
        svc = SigningService()
        svc.generate("release-key-9", "release")
        with mock.patch.dict(os.environ, {PASSPHRASE_ENV: "unit-test-only-passphrase"}):
            with self.assertRaises(KeyLocationError):
                svc.export_key("release-key-9", PHASE2 / "keys", repo_root=PHASE2)
            self.assertFalse((PHASE2 / "keys").exists())
            with tempfile.TemporaryDirectory() as outside:
                path = svc.export_key("release-key-9", outside, repo_root=PHASE2)
                pem = path.read_bytes()
                self.assertIn(b"ENCRYPTED PRIVATE KEY", pem)          # never stored in clear
                with self.assertRaises(TypeError):
                    serialization.load_pem_private_key(pem, None)
                other = SigningService()
                self.assertEqual(other.load_key(path, repo_root=PHASE2), "release-key-9")
        with mock.patch.dict(os.environ, {}, clear=True):
            with tempfile.TemporaryDirectory() as outside, self.assertRaises(KeyLocationError):
                svc.export_key("release-key-9", outside, repo_root=PHASE2)

    def test_QT_01_repository_contains_no_secrets(self):
        """QT-01 | B-09 | SR-10"""
        files = scan_secrets.candidate_files([])
        self.assertGreater(len(files), 20)
        self.assertEqual(scan_secrets.scan(files), [])
        # positive control: the scanner does find a real private key and a key file
        with tempfile.TemporaryDirectory() as tmp:
            pem = Ed25519PrivateKey.generate().private_bytes(
                serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption())
            (Path(tmp) / "notes.txt").write_bytes(b"config\n" + pem)
            (Path(tmp) / "release.key").write_bytes(b"x")
            rules = {rule for _f, _l, rule in scan_secrets.scan(scan_secrets.candidate_files([tmp]))}
            self.assertEqual(rules, {"private-key-block", "key-file-in-tree"})

    def test_QT_02_logs_and_audit_carry_no_secrets(self):
        """QT-02 | B-07 | NFR-05"""
        from .fleet import Fleet
        with tempfile.TemporaryDirectory() as tmp:
            fleet = Fleet(tmp)
            rid = fleet.release("ECU-A", 2)
            fleet.campaign([rid])
            fleet.poll_and_stage("qt02-cid-0001")
            fleet.gateway.build_manifest("qt02-cid-0002")
            texts = [Path(tmp, "vehicle", "audit.jsonl").read_text(encoding="utf-8"),
                     repr(fleet.backend.audit.events), repr(fleet.signer.usage_log)]
            secrets_ = list(fleet.tokens.values())
            for key in fleet.signer._keys.values():
                raw = key.private.private_bytes(serialization.Encoding.Raw,
                                                serialization.PrivateFormat.Raw,
                                                serialization.NoEncryption())
                secrets_ += [raw.hex(), raw.hex().upper()]
            for text in texts:
                for s in secrets_:
                    self.assertNotIn(s, text)
                self.assertNotIn("PRIVATE KEY", text)
            evidence = PHASE2 / "evidence"
            if evidence.exists():                     # previous run_all output, if any
                self.assertEqual(scan_secrets.scan(scan_secrets.candidate_files([str(evidence)])), [])

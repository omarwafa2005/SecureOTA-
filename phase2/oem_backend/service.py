"""OEM backend service layer (Student 2, S2-T1 to S2-T3).

Concepts: Vehicle, ECU, Artifact, Release, Campaign, Assignment, Manifest,
AuditEvent (see docs/student2_backend_spec.md for the data model).

Rules this module enforces:
  * every public method takes a Principal and a correlation ID, checks the
    authorization matrix first, and writes exactly one audit event with the
    outcome SUCCESS, DENIED or FAILED (SR-08, SR-09, NFR-02)
  * every state change runs in a transaction: on any error the whole data
    store is restored, so a failed request never leaves a partial change
  * signed target content is built only from approved release records, so
    editing an assignment or campaign cannot silently change what a vehicle
    installs (S2-T3 completion check; threat B-04)
  * event reports are idempotent by event_id (FR-13, threat B-08)

Storage is in memory. A database and object store replace `_db` and `_blobs`
in the implementation phase; the transaction and audit rules stay the same.
"""
from __future__ import annotations

import copy
import hashlib
import json
import re
import time
from contextlib import contextmanager
from typing import Callable, Iterable, Optional

from security.keys import load_public
from security.signing import SigningRefused, SigningService
from vehicle.gateway import verify_manifest

from .audit import AuditTrail
from .auth import AUTHZ_MATRIX, Principal, allowed
from .errors import ApiError

ID_RE = re.compile(r"^[A-Z0-9][A-Z0-9-]{2,63}$")
EVENT_ID_RE = re.compile(r"^[A-Za-z0-9-]{8,64}$")
HEX64_RE = re.compile(r"^[0-9a-f]{64}$")

EVENT_OUTCOMES = ("STAGED", "INSTALLED", "CONFIRMED", "REJECTED", "ROLLED_BACK", "POSTPONED")
TRANSITIONS = {
    "OFFERED": {"STAGED", "REJECTED"},
    "STAGED": {"INSTALLED", "REJECTED", "POSTPONED"},
    "INSTALLED": {"CONFIRMED", "ROLLED_BACK"},
}
STATUS_LABELS = {                                   # US-01 operator view
    "OFFERED": "Offered to vehicle",
    "STAGED": "Staged (inactive slot)",
    "INSTALLED": "Active - awaiting health confirmation",
    "CONFIRMED": "Active - confirmed",
    "REJECTED": "Failed - rejected",
    "ROLLED_BACK": "Rolled back to previous version",
}
MIN_EXPIRY_S, MAX_EXPIRY_S = 60, 30 * 24 * 3600


def _require(cond: bool, code: str, category: str = "VALIDATION_FAILED"):
    if not cond:
        raise ApiError(category, code)


def _is_int(x) -> bool:
    return isinstance(x, int) and not isinstance(x, bool)


def _exact_keys(body, required: set, optional: set = frozenset()):
    _require(isinstance(body, dict), "BODY_NOT_OBJECT")
    _require(set(body) <= required | optional, "UNEXPECTED_FIELD")      # PR-01, strict input
    _require(required <= set(body), "MISSING_FIELD")


def dependency_order(ecus: list[str], deps: dict) -> list[str]:
    """Topological order of ECUs; raises ApiError(DEPENDENCY_CYCLE) with a diagnostic (FR-14)."""
    order, state = [], {}

    def visit(node, path):
        if state.get(node) == "done":
            return
        if state.get(node) == "active":
            cycle = path[path.index(node):] + [node]
            raise ApiError("VALIDATION_FAILED", "DEPENDENCY_CYCLE",
                           diagnostic=" -> ".join(cycle))
        state[node] = "active"
        for dep in deps.get(node, []):
            visit(dep, path + [node])
        state[node] = "done"
        order.append(node)

    for ecu in sorted(ecus):
        visit(ecu, [])
    return order


class BackendService:
    def __init__(self, *, signer: SigningService, release_key_id: str,
                 audit: Optional[AuditTrail] = None, clock: Callable[[], float] = time.time,
                 max_artifact_bytes: int = 16 * 1024 * 1024, chunk_size: int = 64 * 1024):
        self._signer = signer
        self._release_key_id = release_key_id
        self._clock = clock
        self.audit = audit or AuditTrail(clock)
        self.max_artifact_bytes = max_artifact_bytes
        self.chunk_size = chunk_size
        self._db = {"vehicles": {}, "artifacts": {}, "releases": {}, "campaigns": {},
                    "assignments": {}, "events": {}, "md_counter": {}}
        self._blobs: dict[str, bytes] = {}

    # ------------------------------------------------------------ plumbing
    @contextmanager
    def _tx(self):
        snapshot = copy.deepcopy(self._db)
        try:
            yield
        except BaseException:
            self._db = snapshot
            raise

    def _op(self, p: Principal, action: str, obj: str, cid: str, fn,
            vehicle_id: Optional[str] = None):
        """Authorize, run in a transaction, audit the outcome."""
        if not cid:
            raise ApiError("VALIDATION_FAILED", "MISSING_CORRELATION_ID")
        own_vehicle_ok = (vehicle_id is None or "vehicle" not in AUTHZ_MATRIX[action]
                          or p.vehicle_id == vehicle_id)
        if not allowed(p, action) or not own_vehicle_ok:
            self.audit.record(actor=p.name, action=action, obj=obj, outcome="DENIED",
                              correlation_id=cid)
            raise ApiError("FORBIDDEN")
        try:
            with self._tx():
                result = fn()
        except ApiError as err:
            outcome = "DENIED" if err.category == "FORBIDDEN" else "FAILED"
            self.audit.record(actor=p.name, action=action, obj=obj, outcome=outcome,
                              correlation_id=cid, code=err.code)
            raise
        self.audit.record(actor=p.name, action=action, obj=obj, outcome="SUCCESS",
                          correlation_id=cid)
        return result

    def _vehicle(self, vehicle_id: str) -> dict:
        v = self._db["vehicles"].get(vehicle_id)
        _require(v is not None, "UNKNOWN_VEHICLE", "NOT_FOUND")
        return v

    # ---------------------------------------------------------- UC-01
    def register_vehicle(self, p: Principal, body: dict, cid: str) -> dict:
        """FR-01, PR-01: identities and hardware IDs only; no personal data."""
        def run():
            _exact_keys(body, {"vehicle_id", "ecus", "manifest_key_id", "manifest_public_key"})
            vid = body["vehicle_id"]
            _require(isinstance(vid, str) and ID_RE.match(vid) is not None, "INVALID_IDENTITY")
            _require(vid not in self._db["vehicles"], "DUPLICATE_VEHICLE", "CONFLICT")
            _require(isinstance(body["manifest_key_id"], str) and body["manifest_key_id"] != "",
                     "INVALID_KEY")
            _require(isinstance(body["manifest_public_key"], str)
                     and HEX64_RE.match(body["manifest_public_key"]) is not None, "INVALID_KEY")
            ecus = body["ecus"]
            _require(isinstance(ecus, list) and ecus, "NO_ECUS")
            records = {}
            for e in ecus:
                _exact_keys(e, {"ecu_id", "hardware_id"})
                for f in ("ecu_id", "hardware_id"):
                    _require(isinstance(e[f], str) and ID_RE.match(e[f]) is not None,
                             "INVALID_IDENTITY")
                _require(e["ecu_id"] not in records, "DUPLICATE_ECU", "CONFLICT")
                records[e["ecu_id"]] = {"hardware_id": e["hardware_id"], "active_version": None,
                                        "confirmed_version": None, "update_state": None}
            self._db["vehicles"][vid] = {"vehicle_id": vid, "ecus": records,
                                         "manifest_key_id": body["manifest_key_id"],
                                         "manifest_public_key": body["manifest_public_key"],
                                         "last_manifest_at": 0}
            return {"vehicle_id": vid, "ecus": sorted(records)}
        return self._op(p, "register_vehicle", str(body.get("vehicle_id", "-"))
                        if isinstance(body, dict) else "-", cid, run)

    # ---------------------------------------------------------- UC-02
    def upload_artifact(self, p: Principal, data: bytes, ecu_id: str, hardware_id: str,
                        cid: str) -> dict:
        """SR-01 digest + length; SR-19 size limit; identical upload is idempotent."""
        def run():
            _require(isinstance(data, (bytes, bytearray)), "BODY_NOT_BYTES")
            _require(len(data) <= self.max_artifact_bytes, "ARTIFACT_TOO_LARGE",
                     "PAYLOAD_TOO_LARGE")
            _require(len(data) > 0, "EMPTY_ARTIFACT")
            for v in (ecu_id, hardware_id):
                _require(isinstance(v, str) and ID_RE.match(v) is not None, "INVALID_IDENTITY")
            digest = hashlib.sha256(data).hexdigest()
            aid = "art-" + digest[:16]
            existing = self._db["artifacts"].get(aid)
            if existing:
                _require(existing["sha256"] == digest and existing["ecu_id"] == ecu_id
                         and existing["hardware_id"] == hardware_id, "ARTIFACT_CONFLICT",
                         "CONFLICT")
            else:
                self._db["artifacts"][aid] = {"artifact_id": aid, "sha256": digest,
                                              "length": len(data), "ecu_id": ecu_id,
                                              "hardware_id": hardware_id,
                                              "uploaded_by": p.name}
                self._blobs[aid] = bytes(data)
            a = self._db["artifacts"][aid]
            return {k: a[k] for k in ("artifact_id", "sha256", "length", "ecu_id", "hardware_id")}
        return self._op(p, "upload_artifact", f"artifact:{ecu_id}", cid, run)

    # ---------------------------------------------------------- UC-03
    def create_release(self, p: Principal, body: dict, cid: str) -> dict:
        def run():
            _exact_keys(body, {"artifact_id", "version"})
            art = self._db["artifacts"].get(body["artifact_id"])
            _require(art is not None, "UNKNOWN_ARTIFACT", "NOT_FOUND")
            _require(_is_int(body["version"]) and body["version"] >= 1, "INVALID_VERSION")
            for r in self._db["releases"].values():
                _require(not (r["ecu_id"] == art["ecu_id"] and r["hardware_id"] == art["hardware_id"]
                              and r["version"] == body["version"]), "VERSION_EXISTS", "CONFLICT")
            rid = f"REL-{len(self._db['releases']) + 1:04d}"
            self._db["releases"][rid] = {
                "release_id": rid, "artifact_id": art["artifact_id"], "ecu_id": art["ecu_id"],
                "hardware_id": art["hardware_id"], "version": body["version"],
                "sha256": art["sha256"], "length": art["length"], "state": "DRAFT",
                "created_by": p.name, "approved_by": None}
            return {"release_id": rid, "state": "DRAFT"}
        return self._op(p, "create_release", f"release:{body.get('artifact_id', '-')}"
                        if isinstance(body, dict) else "-", cid, run)

    def approve_release(self, p: Principal, release_id: str, cid: str) -> dict:
        """SR-18: the approver must not be the creator."""
        def run():
            r = self._db["releases"].get(release_id)
            _require(r is not None, "UNKNOWN_RELEASE", "NOT_FOUND")
            _require(r["state"] == "DRAFT", "NOT_DRAFT", "CONFLICT")
            _require(r["created_by"] != p.name, "SEPARATION_OF_DUTIES", "FORBIDDEN")
            r["state"], r["approved_by"] = "APPROVED", p.name
            return {"release_id": release_id, "state": "APPROVED"}
        return self._op(p, "approve_release", f"release:{release_id}", cid, run)

    # ---------------------------------------------------------- UC-04
    def create_campaign(self, p: Principal, body: dict, cid: str) -> dict:
        """FR-07: explicit targets and policy; FR-14: dependency cycles rejected."""
        def run():
            _exact_keys(body, {"release_ids", "targets", "policy"}, {"dependencies"})
            rids, targets, policy = body["release_ids"], body["targets"], body["policy"]
            _require(isinstance(rids, list) and rids, "NO_RELEASES")
            _require(isinstance(targets, list) and targets
                     and len(set(targets)) == len(targets), "INVALID_TARGETS")
            _exact_keys(policy, {"expires_in_s", "require_safe_state"})
            _require(_is_int(policy["expires_in_s"])
                     and MIN_EXPIRY_S <= policy["expires_in_s"] <= MAX_EXPIRY_S, "INVALID_POLICY")
            _require(policy["require_safe_state"] is True, "INVALID_POLICY")  # cannot be disabled
            releases = []
            for rid in rids:
                r = self._db["releases"].get(rid)
                _require(r is not None, "UNKNOWN_RELEASE", "NOT_FOUND")
                _require(r["state"] == "APPROVED", "RELEASE_NOT_APPROVED", "CONFLICT")
                releases.append(r)
            ecus = [r["ecu_id"] for r in releases]
            _require(len(set(ecus)) == len(ecus), "DUPLICATE_ECU_RELEASE")
            for vid in targets:
                _require(isinstance(vid, str) and vid in self._db["vehicles"], "UNKNOWN_TARGET")
                v = self._db["vehicles"][vid]
                _require(any(v["ecus"].get(r["ecu_id"], {}).get("hardware_id") == r["hardware_id"]
                             for r in releases), "INCOMPATIBLE_TARGET")
            deps = body.get("dependencies", {})
            _require(isinstance(deps, dict), "INVALID_DEPENDENCIES")
            for ecu, needs in deps.items():
                _require(ecu in ecus and isinstance(needs, list)
                         and all(n in ecus for n in needs), "INVALID_DEPENDENCIES")
            order = dependency_order(ecus, deps)
            cmp_id = f"CMP-{len(self._db['campaigns']) + 1:04d}"
            self._db["campaigns"][cmp_id] = {
                "campaign_id": cmp_id, "release_ids": list(rids), "targets": list(targets),
                "policy": dict(policy), "dependencies": copy.deepcopy(deps),
                "ecu_order": order, "state": "DRAFT", "created_by": p.name}
            return {"campaign_id": cmp_id, "state": "DRAFT", "ecu_order": order}
        return self._op(p, "create_campaign", "campaign:new", cid, run)

    def _set_campaign_state(self, p, action, campaign_id, cid, allowed_from, new_state):
        def run():
            c = self._db["campaigns"].get(campaign_id)
            _require(c is not None, "UNKNOWN_CAMPAIGN", "NOT_FOUND")
            _require(c["state"] in allowed_from, "INVALID_CAMPAIGN_STATE", "CONFLICT")
            c["state"] = new_state
            return {"campaign_id": campaign_id, "state": new_state}
        return self._op(p, action, f"campaign:{campaign_id}", cid, run)

    def start_campaign(self, p, campaign_id, cid):
        return self._set_campaign_state(p, "start_campaign", campaign_id, cid,
                                        ("DRAFT", "PAUSED"), "RUNNING")

    def pause_campaign(self, p, campaign_id, cid):
        """FR-16: a paused campaign offers nothing new."""
        return self._set_campaign_state(p, "pause_campaign", campaign_id, cid,
                                        ("RUNNING",), "PAUSED")

    # ---------------------------------------------------------- UC-05
    def _sign_offer(self, c: dict, r: dict, vid: str) -> dict:
        key = f"{vid}|{r['ecu_id']}"
        self._db["md_counter"][key] = self._db["md_counter"].get(key, 0) + 1
        payload = {"artifact_id": r["artifact_id"], "campaign_id": c["campaign_id"],
                   "vehicle_id": vid, "ecu_id": r["ecu_id"], "hardware_id": r["hardware_id"],
                   "version": r["version"], "metadata_version": self._db["md_counter"][key],
                   "length": r["length"], "sha256": r["sha256"],
                   "expires_at": int(self._clock()) + c["policy"]["expires_in_s"]}
        try:
            return self._signer.sign_target(payload, r, self._release_key_id)
        except SigningRefused as refused:
            raise ApiError("CONFLICT", "SIGNING_REFUSED") from refused

    def get_instructions(self, p: Principal, vehicle_id: str, cid: str) -> dict:
        """FR-02: signed per-vehicle targets for eligible ECUs only."""
        def run():
            v = self._vehicle(vehicle_id)
            bundles = []
            for c in self._db["campaigns"].values():
                if c["state"] != "RUNNING" or vehicle_id not in c["targets"]:
                    continue
                by_ecu = {self._db["releases"][rid]["ecu_id"]: self._db["releases"][rid]
                          for rid in c["release_ids"]}
                envelopes = []
                for ecu_id in c["ecu_order"]:
                    r = by_ecu[ecu_id]
                    ecu = v["ecus"].get(ecu_id)
                    if ecu is None or ecu["hardware_id"] != r["hardware_id"]:
                        continue                                    # not this vehicle's ECU
                    if ecu["active_version"] is not None and ecu["active_version"] >= r["version"]:
                        continue                                    # already at or above
                    akey = f"{c['campaign_id']}|{vehicle_id}|{ecu_id}"
                    a = self._db["assignments"].get(akey)
                    if a and a["state"] != "OFFERED":
                        continue                                    # in progress or finished
                    if a and a["envelope"]["signed"]["expires_at"] > self._clock():
                        envelopes.append(a["envelope"])             # same offer again (FR-11)
                        continue
                    env = self._sign_offer(c, r, vehicle_id)
                    self._db["assignments"][akey] = {
                        "campaign_id": c["campaign_id"], "vehicle_id": vehicle_id,
                        "ecu_id": ecu_id, "release_id": r["release_id"], "state": "OFFERED",
                        "metadata_version": env["signed"]["metadata_version"],
                        "envelope": env, "reason": None, "history": ["OFFERED"]}
                    envelopes.append(env)
                if envelopes:
                    bundles.append({"campaign_id": c["campaign_id"], "targets": envelopes})
            return {"vehicle_id": vehicle_id, "bundles": copy.deepcopy(bundles)}
        return self._op(p, "get_instructions", f"vehicle:{vehicle_id}", cid, run,
                        vehicle_id=vehicle_id)

    # ---------------------------------------------------------- UC-06
    def download_artifact(self, p: Principal, artifact_id: str, cid: str) -> bytes:
        """Least privilege: a vehicle may fetch only artifacts offered to it."""
        def run():
            offered = any(a["vehicle_id"] == p.vehicle_id and
                          self._db["releases"][a["release_id"]]["artifact_id"] == artifact_id
                          for a in self._db["assignments"].values())
            _require(offered and artifact_id in self._blobs, "UNKNOWN_ARTIFACT", "NOT_FOUND")
            return self._blobs[artifact_id]
        return self._op(p, "download_artifact", f"artifact:{artifact_id}", cid, run)

    def fetcher(self, p: Principal, cid: str):
        """Adapter to the gateway's Fetch interface (yields chunks)."""
        def fetch(artifact_id: str, _sha256: str) -> Iterable[bytes]:
            try:
                data = self.download_artifact(p, artifact_id, cid)
            except ApiError as err:
                raise ConnectionError(err.category) from None
            for i in range(0, len(data), self.chunk_size):
                yield data[i:i + self.chunk_size]
        return fetch

    # ---------------------------------------------------------- events
    def report_event(self, p: Principal, vehicle_id: str, body: dict, cid: str) -> dict:
        """FR-12 assignment state; FR-13 exactly-once by event_id."""
        def run():
            _exact_keys(body, {"event_id", "campaign_id", "ecu_id", "outcome",
                               "metadata_version"}, {"reason"})
            eid = body["event_id"]
            _require(isinstance(eid, str) and EVENT_ID_RE.match(eid) is not None,
                     "INVALID_EVENT_ID")
            digest = hashlib.sha256(json.dumps({"v": vehicle_id, **body}, sort_keys=True)
                                    .encode()).hexdigest()
            seen = self._db["events"].get(eid)
            if seen:
                _require(seen["digest"] == digest, "EVENT_ID_REUSED", "CONFLICT")
                return dict(seen["result"], duplicate=True)
            _require(body["outcome"] in EVENT_OUTCOMES, "INVALID_OUTCOME")
            reason = body.get("reason", "")
            _require(isinstance(reason, str) and len(reason) <= 64, "INVALID_REASON")
            akey = f"{body['campaign_id']}|{vehicle_id}|{body['ecu_id']}"
            a = self._db["assignments"].get(akey)
            _require(a is not None, "UNKNOWN_ASSIGNMENT", "NOT_FOUND")
            _require(body["metadata_version"] == a["metadata_version"], "STALE_EVENT", "CONFLICT")
            _require(body["outcome"] in TRANSITIONS.get(a["state"], set()),
                     "INVALID_TRANSITION", "CONFLICT")
            if body["outcome"] != "POSTPONED":
                a["state"] = body["outcome"]
            a["reason"] = reason or None
            a["history"].append(body["outcome"])
            result = {"assignment_state": a["state"], "duplicate": False}
            self._db["events"][eid] = {"digest": digest, "result": result}
            return dict(result)
        return self._op(p, "report_event", f"vehicle:{vehicle_id}", cid, run,
                        vehicle_id=vehicle_id)

    # ---------------------------------------------------------- manifest
    def submit_manifest(self, p: Principal, vehicle_id: str, envelope: dict, cid: str) -> dict:
        """SR-20: accept only a fresh, complete manifest signed by the registered vehicle key."""
        def run():
            v = self._vehicle(vehicle_id)
            try:
                trusted = {v["manifest_key_id"]: load_public(v["manifest_public_key"])}
            except ValueError:
                raise ApiError("INTERNAL") from None
            reason, payload = verify_manifest(envelope, trusted)
            _require(reason is None, reason.value if reason else "", "VALIDATION_FAILED")
            _require(payload["vehicle_id"] == vehicle_id, "VEHICLE_MISMATCH")
            gen = payload.get("generated_at")
            _require(_is_int(gen), "MALFORMED_METADATA")
            _require(gen > v["last_manifest_at"], "STALE_MANIFEST", "CONFLICT")
            reported = {}
            for e in payload["ecus"]:
                _require(isinstance(e, dict) and isinstance(e.get("ecu_id"), str),
                         "MANIFEST_INCONSISTENT")
                known = v["ecus"].get(e["ecu_id"])
                _require(known is not None and known["hardware_id"] == e.get("hardware_id"),
                         "MANIFEST_INCONSISTENT")
                reported[e["ecu_id"]] = e
            _require(set(reported) == set(v["ecus"]), "MANIFEST_INCOMPLETE")
            for ecu_id, e in reported.items():
                v["ecus"][ecu_id].update(active_version=e.get("active_version"),
                                         confirmed_version=e.get("confirmed_version"),
                                         update_state=e.get("update_state"))
            v["last_manifest_at"] = gen
            return {"accepted": True, "ecus": sorted(reported)}
        return self._op(p, "submit_manifest", f"vehicle:{vehicle_id}", cid, run,
                        vehicle_id=vehicle_id)

    # ---------------------------------------------------------- UC-11 / US-01
    def campaign_status(self, p: Principal, campaign_id: str, cid: str) -> dict:
        def run():
            c = self._db["campaigns"].get(campaign_id)
            _require(c is not None, "UNKNOWN_CAMPAIGN", "NOT_FOUND")
            rows = [{"vehicle_id": a["vehicle_id"], "ecu_id": a["ecu_id"], "state": a["state"],
                     "label": STATUS_LABELS[a["state"]], "reason": a["reason"]}
                    for a in self._db["assignments"].values()
                    if a["campaign_id"] == campaign_id]
            return {"campaign_id": campaign_id, "state": c["state"],
                    "assignments": sorted(rows, key=lambda r: (r["vehicle_id"], r["ecu_id"]))}
        return self._op(p, "view_status", f"campaign:{campaign_id}", cid, run)

    def query_audit(self, p: Principal, cid: str, **filters) -> dict:
        def run():
            ok, bad = self.audit.verify()
            return {"chain_intact": ok, "first_bad_seq": bad,
                    "events": self.audit.query(**filters)}
        return self._op(p, "query_audit", "audit", cid, run)

"""Vehicle gateway: verifies instructions, downloads, and routes updates to ECUs.

Verification order (fail fast, nothing touches an ECU until every check passes):
  1. signature under an authorized, non-revoked key        SR-03, SR-04
  2. strict field validation                               SR-07
  3. expiry against the trusted clock                      SR-07 / T-07
  4. vehicle and campaign consistency                      SR-07 / T-06
  5. target binding: ecu_id and hardware_id                SR-05 / T-05
  6. replay: metadata_version vs last accepted             SR-07 / T-03
  7. anti-rollback vs ECU trusted_min_version              SR-06 / T-04
  8. declared length vs max_artifact_bytes                 SR-12 / T-08
  9. bounded, timed download of the exact artifact         FR-03, NFR-04, SR-12
 10. exact length and SHA-256 digest                       SR-02 / T-01
 11. stage on the ECU (which re-checks 5, 7 and 10)        FR-04

Gateway-to-ECU calls are in-process in Phase 2. Authenticating those calls on
a real vehicle network is a recorded residual risk (threat V-01).

`fetch(artifact_id, sha256)` yields byte chunks. Stall and total timeouts are
checked between chunks using the injected monotonic clock; a real transport
must also set socket read timeouts to stall_timeout_s.
"""
from __future__ import annotations

import copy
import hmac
import json
import time
from pathlib import Path
from typing import Callable, Iterable, Mapping, Optional

from .audit import AuditLog, new_correlation_id
from .ecu import Ecu, atomic_write, sha256_hex
from .errors import Reason, Result
from .metadata import payload_digest, sign_envelope, validate_target, verify_envelope
from .safety import VehicleConditions

Fetch = Callable[[str, str], Iterable[bytes]]


class Gateway:
    COMPONENT = "gateway"
    STATE_FILE = "gateway_state.json"

    def __init__(self, *, vehicle_id: str, ecus: Iterable[Ecu], trusted_keys: Mapping,
                 state_dir, revoked_key_ids: Iterable[str] = (),
                 manifest_key=None, manifest_key_id: str = "vehicle-key",
                 clock: Callable[[], float] = time.time,
                 monotonic: Callable[[], float] = time.monotonic,
                 max_artifact_bytes: int = 16 * 1024 * 1024,
                 stall_timeout_s: float = 10.0, total_timeout_s: float = 300.0,
                 audit: Optional[AuditLog] = None,
                 fault_hook: Optional[Callable[[str], None]] = None):
        self.vehicle_id = vehicle_id
        self.ecus: dict[str, Ecu] = {}
        for ecu in ecus:
            if ecu.ecu_id in self.ecus:
                raise ValueError("duplicate ECU identity")
            self.ecus[ecu.ecu_id] = ecu
        self.trusted_keys = dict(trusted_keys)
        self.revoked_key_ids = frozenset(revoked_key_ids)
        self._manifest_key = manifest_key
        self.manifest_key_id = manifest_key_id
        self._clock = clock
        self._mono = monotonic
        self.max_artifact_bytes = max_artifact_bytes
        self.stall_timeout_s = stall_timeout_s
        self.total_timeout_s = total_timeout_s
        self.audit = audit or AuditLog()
        self._fault = fault_hook or (lambda name: None)
        self._state_path = Path(state_dir) / self.STATE_FILE
        if self._state_path.exists():
            self._state = json.loads(self._state_path.read_text(encoding="utf-8"))
        else:
            self._state = {"accepted": {}}

    # ------------------------------------------------------------- helpers
    def _reject(self, cid: str, reason: Reason, step: str, **fields) -> Result:
        self.audit.record(cid, self.COMPONENT, step, "REJECTED", reason=reason.value, **fields)
        return Result(False, reason, cid)

    def accepted_metadata_version(self, ecu_id: str) -> int:
        entry = self._state["accepted"].get(ecu_id)
        return entry["metadata_version"] if entry else 0

    def _record_accepted(self, payload: dict) -> None:
        new = copy.deepcopy(self._state)
        new["accepted"][payload["ecu_id"]] = {
            "metadata_version": payload["metadata_version"],
            "payload_sha256": payload_digest(payload)}
        atomic_write(self._state_path, json.dumps(new, sort_keys=True).encode())
        self._state = new

    # --------------------------------------------------------- verification
    def _check(self, envelope, expected_campaign: Optional[str]):
        """Steps 1-8. Returns (reason_or_None, payload, ecu, idempotent)."""
        reason, payload = verify_envelope(envelope, self.trusted_keys, self.revoked_key_ids)
        if reason:
            return reason, None, None, False
        reason = validate_target(payload)
        if reason:
            return reason, None, None, False
        if payload["expires_at"] <= self._clock():
            return Reason.EXPIRED_METADATA, payload, None, False
        if payload["vehicle_id"] != self.vehicle_id:
            return Reason.INCONSISTENT_METADATA, payload, None, False
        if expected_campaign is not None and payload["campaign_id"] != expected_campaign:
            return Reason.INCONSISTENT_METADATA, payload, None, False
        ecu = self.ecus.get(payload["ecu_id"])
        if ecu is None or payload["hardware_id"] != ecu.hardware_id:
            return Reason.WRONG_TARGET, payload, None, False
        accepted = self._state["accepted"].get(ecu.ecu_id)
        if accepted:
            if payload["metadata_version"] < accepted["metadata_version"]:
                return Reason.REPLAYED_METADATA, payload, ecu, False
            if payload["metadata_version"] == accepted["metadata_version"]:
                if payload_digest(payload) == accepted["payload_sha256"]:
                    return None, payload, ecu, True          # FR-11 idempotent repeat
                return Reason.INCONSISTENT_METADATA, payload, ecu, False
        if payload["version"] < ecu.trusted_min_version:
            return Reason.ROLLBACK_REJECTED, payload, ecu, False
        if payload["version"] == ecu.confirmed_version:
            return Reason.ALREADY_INSTALLED, payload, ecu, False
        if payload["length"] > self.max_artifact_bytes:
            return Reason.ARTIFACT_TOO_LARGE, payload, ecu, False
        return None, payload, ecu, False

    def _download(self, fetch: Fetch, payload: dict):
        """Step 9-10. Returns (reason_or_None, image)."""
        limit = payload["length"]
        start = last_progress = self._mono()
        buf = bytearray()
        stream = iter(fetch(payload["artifact_id"], payload["sha256"]))
        try:
            for chunk in stream:
                now = self._mono()
                if now - last_progress > self.stall_timeout_s or now - start > self.total_timeout_s:
                    return Reason.DOWNLOAD_TIMEOUT, None
                if not isinstance(chunk, (bytes, bytearray)):
                    return Reason.NETWORK_ERROR, None
                if chunk:
                    last_progress = now
                    buf.extend(chunk)
                if len(buf) > limit:
                    return Reason.ARTIFACT_TOO_LARGE, None
        except (ConnectionError, TimeoutError, OSError):
            return Reason.NETWORK_ERROR, None
        finally:
            close = getattr(stream, "close", None)
            if close:
                close()
        if len(buf) != limit:
            return Reason.LENGTH_MISMATCH, None
        if not hmac.compare_digest(sha256_hex(bytes(buf)), payload["sha256"]):
            return Reason.DIGEST_MISMATCH, None
        return None, bytes(buf)

    # ----------------------------------------------------------- public API
    def process_update(self, envelope, fetch: Fetch, correlation_id: Optional[str] = None,
                       expected_campaign: Optional[str] = None) -> Result:
        """UC-06 + UC-07: verify, download and stage one target."""
        cid = correlation_id or new_correlation_id()
        reason, payload, ecu, idempotent = self._check(envelope, expected_campaign)
        ecu_id = payload["ecu_id"] if payload else None
        if reason:
            return self._reject(cid, reason, "verify_metadata", ecu_id=ecu_id)
        if idempotent:
            self.audit.record(cid, self.COMPONENT, "verify_metadata", "ALREADY_APPLIED",
                              ecu_id=ecu_id, metadata_version=payload["metadata_version"])
            return Result(True, Reason.ALREADY_APPLIED, cid)
        self.audit.record(cid, self.COMPONENT, "verify_metadata", "ACCEPTED", ecu_id=ecu_id,
                          version=payload["version"], metadata_version=payload["metadata_version"])

        reason, image = self._download(fetch, payload)
        if reason:
            return self._reject(cid, reason, "download", ecu_id=ecu_id,
                                artifact_id=payload["artifact_id"])
        self.audit.record(cid, self.COMPONENT, "download", "VERIFIED", ecu_id=ecu_id,
                          artifact_id=payload["artifact_id"], length=len(image))

        result = ecu.stage(image, payload, cid)
        if not result.ok:
            return self._reject(cid, result.reason, "stage", ecu_id=ecu_id)
        self._fault("gateway:before_record")
        self._record_accepted(payload)
        return result

    def process_bundle(self, bundle, fetch: Fetch,
                       correlation_id: Optional[str] = None) -> dict[str, Result]:
        """Campaign instruction bundle {"campaign_id", "targets": [envelopes]}.

        Every envelope is verified before any download. One inconsistent or
        invalid envelope rejects the whole bundle (T-06). Returns
        {ecu_id: Result}, or {"*": Result} for a bundle-level rejection.
        """
        cid = correlation_id or new_correlation_id()
        if (not isinstance(bundle, dict) or not isinstance(bundle.get("campaign_id"), str)
                or not isinstance(bundle.get("targets"), list) or not bundle["targets"]):
            return {"*": self._reject(cid, Reason.MALFORMED_METADATA, "verify_bundle")}
        campaign = bundle["campaign_id"]
        seen = set()
        for env in bundle["targets"]:
            reason, payload, _ecu, _idem = self._check(env, campaign)
            if reason:
                return {"*": self._reject(cid, reason, "verify_bundle", campaign_id=campaign)}
            if payload["ecu_id"] in seen:
                return {"*": self._reject(cid, Reason.INCONSISTENT_METADATA, "verify_bundle",
                                          campaign_id=campaign)}
            seen.add(payload["ecu_id"])
        return {env["signed"]["ecu_id"]: self.process_update(env, fetch, cid, campaign)
                for env in bundle["targets"]}

    def activate(self, ecu_id: str, conditions: VehicleConditions,
                 correlation_id: Optional[str] = None) -> Result:
        cid = correlation_id or new_correlation_id()
        ecu = self.ecus.get(ecu_id)
        if ecu is None:
            return self._reject(cid, Reason.WRONG_TARGET, "activate")
        return ecu.activate(conditions, cid)

    def build_manifest(self, correlation_id: Optional[str] = None) -> dict:
        """FR-08 / SR-13: signed vehicle version manifest."""
        if self._manifest_key is None:
            raise RuntimeError("no vehicle manifest key provisioned")
        cid = correlation_id or new_correlation_id()
        payload = {"vehicle_id": self.vehicle_id, "generated_at": int(self._clock()),
                   "correlation_id": cid,
                   "ecus": [self.ecus[k].report() for k in sorted(self.ecus)]}
        self.audit.record(cid, self.COMPONENT, "manifest", "SIGNED", ecu_count=len(self.ecus))
        return sign_envelope(payload, self._manifest_key, self.manifest_key_id)


def verify_manifest(envelope, trusted_vehicle_keys: Mapping) -> tuple[Optional[Reason], Optional[dict]]:
    """Receiver-side manifest check (used by the backend; Student 2 integrates)."""
    reason, payload = verify_envelope(envelope, trusted_vehicle_keys)
    if reason:
        return reason, None
    if not isinstance(payload.get("ecus"), list) or not isinstance(payload.get("vehicle_id"), str):
        return Reason.MALFORMED_METADATA, None
    return None, payload

"""Simulated ECU with A/B slots, durable update state and rollback.

Invariants enforced here:
  * New firmware is only ever written to the inactive slot (SAF-01, SAF-02).
  * Every state change is one atomic file replace, so a power loss leaves
    either the old or the new state, never a mix (SAF-06).
  * The confirmed slot only changes on a positive health confirmation
    (FR-09); any failure path makes the confirmed slot active again (FR-10).

Update states (persisted in state.json):
  IDLE -> STAGING -> STAGED -> INSTALLED -> CONFIRMED
                       |          |
                       v          +--> ROLLED_BACK
                    REJECTED (staged image failed re-verification)

Fault injection: `fault_hook(name)` is called at every name in CHECKPOINTS.
The test bench raises SimulatedPowerLoss there, discards the object, and
re-opens the ECU from disk to model a restart.
"""
from __future__ import annotations

import copy
import hashlib
import hmac
import json
import os
from enum import Enum
from pathlib import Path
from typing import Callable, Optional

from .audit import AuditLog
from .errors import Reason, Result
from .safety import SafetyPolicy, VehicleConditions

SLOTS = ("A", "B")

CHECKPOINTS = (
    "stage:intent_saved",
    "stage:mid_write",
    "stage:image_synced",
    "stage:image_renamed",
    "stage:committed",
    "activate:before_commit",
    "activate:committed",
    "boot:counted",
    "confirm:before_commit",
    "confirm:committed",
    "rollback:before_commit",
    "rollback:committed",
)


class UpdateState(str, Enum):
    IDLE = "IDLE"
    STAGING = "STAGING"
    STAGED = "STAGED"
    INSTALLED = "INSTALLED"      # activated, booting, awaiting health confirmation
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    ROLLED_BACK = "ROLLED_BACK"


class SimulatedPowerLoss(Exception):
    """Raised by the test bench's fault hook to model power loss / process kill."""


def sha256_hex(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def other_slot(slot: str) -> str:
    return "B" if slot == "A" else "A"


def _fsync_dir(directory: Path) -> None:
    try:
        fd = os.open(directory, os.O_RDONLY)
    except OSError:          # not supported on Windows; os.replace is still atomic
        return
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.replace(tmp, path)
    _fsync_dir(path.parent)


class Ecu:
    STATE_FILE = "state.json"
    COMPONENT = "ecu"

    # ------------------------------------------------------------------ setup
    @classmethod
    def provision(cls, root, *, ecu_id: str, hardware_id: str, version: int,
                  image: bytes, **kwargs) -> "Ecu":
        """Factory provisioning: known-good image in slot A, confirmed."""
        root = Path(root)
        root.mkdir(parents=True, exist_ok=True)
        if (root / cls.STATE_FILE).exists():
            raise FileExistsError("ECU already provisioned")
        atomic_write(root / "slot_A.bin", image)
        state = {
            "ecu_id": ecu_id,
            "hardware_id": hardware_id,
            "active_slot": "A",
            "confirmed_slot": "A",
            "slots": {"A": {"version": version, "sha256": sha256_hex(image),
                            "length": len(image)},
                      "B": None},
            "trusted_min_version": version,
            "update_state": UpdateState.IDLE.value,
            "staged_version": None,
            "boot_attempts": 0,
            "last_correlation_id": None,
            "generation": 0,
        }
        atomic_write(root / cls.STATE_FILE, json.dumps(state, sort_keys=True).encode())
        return cls(root, **kwargs)

    def __init__(self, root, *, fault_hook: Optional[Callable[[str], None]] = None,
                 audit: Optional[AuditLog] = None, policy: Optional[SafetyPolicy] = None,
                 max_boot_attempts: int = 3, health_timeout_s: float = 60.0):
        self.root = Path(root)
        self._fault = fault_hook or (lambda name: None)
        self.audit = audit or AuditLog()
        self.policy = policy or SafetyPolicy()
        self.max_boot_attempts = max_boot_attempts
        self.health_timeout_s = health_timeout_s
        self._state = json.loads((self.root / self.STATE_FILE).read_text(encoding="utf-8"))
        self._recover()

    # ------------------------------------------------------------- read-only
    @property
    def ecu_id(self) -> str: return self._state["ecu_id"]
    @property
    def hardware_id(self) -> str: return self._state["hardware_id"]
    @property
    def active_slot(self) -> str: return self._state["active_slot"]
    @property
    def inactive_slot(self) -> str: return other_slot(self._state["active_slot"])
    @property
    def confirmed_slot(self) -> str: return self._state["confirmed_slot"]
    @property
    def update_state(self) -> UpdateState: return UpdateState(self._state["update_state"])
    @property
    def trusted_min_version(self) -> int: return self._state["trusted_min_version"]
    @property
    def staged_version(self) -> Optional[int]: return self._state["staged_version"]
    @property
    def boot_attempts(self) -> int: return self._state["boot_attempts"]

    def slot_record(self, slot: str) -> Optional[dict]:
        rec = self._state["slots"][slot]
        return dict(rec) if rec else None

    @property
    def active_version(self) -> int: return self._state["slots"][self.active_slot]["version"]
    @property
    def confirmed_version(self) -> int: return self._state["slots"][self.confirmed_slot]["version"]

    def slot_path(self, slot: str) -> Path:
        if slot not in SLOTS:
            raise ValueError("unknown slot")
        return self.root / f"slot_{slot}.bin"

    def slot_image_valid(self, slot: str) -> bool:
        rec = self._state["slots"][slot]
        path = self.slot_path(slot)
        if not rec or not path.exists():
            return False
        data = path.read_bytes()
        return len(data) == rec["length"] and hmac.compare_digest(sha256_hex(data), rec["sha256"])

    def report(self) -> dict:
        """Per-ECU entry for the vehicle version manifest (FR-08)."""
        return {"ecu_id": self.ecu_id, "hardware_id": self.hardware_id,
                "active_slot": self.active_slot, "active_version": self.active_version,
                "confirmed_version": self.confirmed_version,
                "staged_version": self.staged_version,
                "update_state": self.update_state.value,
                "trusted_min_version": self.trusted_min_version}

    def snapshot(self) -> dict:
        """Full persistent state plus on-disk slot digests, for 'unchanged' assertions."""
        files = {}
        for slot in SLOTS:
            p = self.slot_path(slot)
            files[slot] = sha256_hex(p.read_bytes()) if p.exists() else None
        return {"state": copy.deepcopy(self._state), "slot_files": files}

    # ------------------------------------------------------------- internals
    def _commit(self, new_state: dict) -> None:
        new_state["generation"] = self._state["generation"] + 1
        atomic_write(self.root / self.STATE_FILE,
                     json.dumps(new_state, sort_keys=True).encode())
        self._state = new_state

    def _event(self, cid: str, action: str, outcome: str, **fields) -> None:
        self.audit.record(cid, self.COMPONENT, action, outcome, ecu_id=self.ecu_id, **fields)

    def _reject(self, cid: str, action: str, reason: Reason, detail=()) -> Result:
        self._event(cid, action, "REJECTED", reason=reason.value)
        return Result(False, reason, cid, tuple(detail))

    def _recover(self) -> None:
        """Bring persisted state to a consistent point after a restart (F-02, F-03)."""
        for tmp in self.root.glob("*.tmp"):
            tmp.unlink()
        if self.update_state is UpdateState.STAGING:
            target = self.inactive_slot
            path = self.slot_path(target)
            if path.exists():
                path.unlink()
            new = copy.deepcopy(self._state)
            new["slots"][target] = None
            new["staged_version"] = None
            new["update_state"] = UpdateState.IDLE.value
            self._commit(new)
            self._event(new.get("last_correlation_id") or "recovery", "recover",
                        "DISCARDED_PARTIAL_STAGING", slot=target)

    # ------------------------------------------------------------ operations
    def stage(self, image: bytes, target: dict, correlation_id: str) -> Result:
        """FR-04: stage a verified artifact in the inactive slot.

        The ECU repeats target binding, anti-rollback, length and digest checks
        even though the gateway already did them (defence in depth).
        """
        cid = correlation_id
        st = self._state
        if self.update_state in (UpdateState.STAGING, UpdateState.INSTALLED):
            return self._reject(cid, "stage", Reason.INVALID_STATE)
        if target["ecu_id"] != st["ecu_id"] or target["hardware_id"] != st["hardware_id"]:
            return self._reject(cid, "stage", Reason.WRONG_TARGET)
        if target["version"] < st["trusted_min_version"]:
            return self._reject(cid, "stage", Reason.ROLLBACK_REJECTED)
        if len(image) != target["length"]:
            return self._reject(cid, "stage", Reason.LENGTH_MISMATCH)
        digest = sha256_hex(image)
        if not hmac.compare_digest(digest, target["sha256"]):
            return self._reject(cid, "stage", Reason.DIGEST_MISMATCH)

        slot = self.inactive_slot
        if slot in (st["active_slot"], st["confirmed_slot"]):
            # Unreachable by construction; kept as an explicit SAF-01/SAF-02 guard
            # (not an assert, so it survives python -O).
            raise RuntimeError("SAF-01 violated: refusing to write the active or confirmed slot")

        existing = st["slots"][slot]
        if (self.update_state is UpdateState.STAGED and existing
                and existing["sha256"] == digest and st["staged_version"] == target["version"]):
            self._event(cid, "stage", "ALREADY_APPLIED", version=target["version"], slot=slot)
            return Result(True, Reason.ALREADY_APPLIED, cid)

        # 1. persist intent: inactive slot is now undefined
        new = copy.deepcopy(st)
        new["update_state"] = UpdateState.STAGING.value
        new["slots"][slot] = None
        new["staged_version"] = None
        new["last_correlation_id"] = cid
        self._commit(new)
        self._fault("stage:intent_saved")

        # 2. write image to a temp file, then atomically rename into the slot
        path = self.slot_path(slot)
        tmp = path.with_name(path.name + ".tmp")
        try:
            with open(tmp, "wb") as f:
                half = len(image) // 2
                f.write(image[:half])
                f.flush()
                self._fault("stage:mid_write")
                f.write(image[half:])
                f.flush()
                os.fsync(f.fileno())
            self._fault("stage:image_synced")
            os.replace(tmp, path)
            _fsync_dir(path.parent)
        except OSError:
            self._recover()
            return self._reject(cid, "stage", Reason.STORAGE_ERROR)
        self._fault("stage:image_renamed")

        # 3. commit staged record
        new = copy.deepcopy(self._state)
        new["slots"][slot] = {"version": target["version"], "sha256": digest,
                              "length": len(image)}
        new["staged_version"] = target["version"]
        new["update_state"] = UpdateState.STAGED.value
        self._commit(new)
        self._fault("stage:committed")
        self._event(cid, "update_state", "STAGED", version=target["version"], slot=slot)
        return Result(True, Reason.OK, cid)

    def activate(self, conditions: VehicleConditions, correlation_id: str) -> Result:
        """Switch to the staged slot when safe (SAF-03, SAF-04, SAF-07, SAF-10)."""
        cid = correlation_id
        if self.update_state is not UpdateState.STAGED:
            return self._reject(cid, "activate", Reason.INVALID_STATE)
        blockers = self.policy.blocking_reasons(conditions)
        if blockers:
            self._event(cid, "activate", "POSTPONED", blockers=list(blockers),
                        version=self.staged_version)
            return Result(False, Reason.ACTIVATION_POSTPONED, cid, blockers)
        slot = self.inactive_slot
        if not self.slot_image_valid(slot):
            new = copy.deepcopy(self._state)
            new["slots"][slot] = None
            new["staged_version"] = None
            new["update_state"] = UpdateState.REJECTED.value
            new["last_correlation_id"] = cid
            self._commit(new)
            return self._reject(cid, "activate", Reason.STORAGE_ERROR, ("STAGED_IMAGE_CORRUPT",))
        self._fault("activate:before_commit")
        new = copy.deepcopy(self._state)
        version = new["staged_version"]
        new["active_slot"] = slot
        new["update_state"] = UpdateState.INSTALLED.value
        new["boot_attempts"] = 0
        new["last_correlation_id"] = cid
        self._commit(new)
        self._fault("activate:committed")
        self._event(cid, "update_state", "INSTALLED", version=version, slot=slot)
        return Result(True, Reason.OK, cid)

    def boot(self, correlation_id: Optional[str] = None) -> str:
        """Simulated reboot. Returns the slot that runs (SAF-05, SAF-09)."""
        cid = correlation_id or self._state.get("last_correlation_id") or "boot"
        if self.update_state is UpdateState.INSTALLED:
            if not self.slot_image_valid(self.active_slot):
                return self._rollback(cid, "ACTIVE_IMAGE_INTEGRITY")
            new = copy.deepcopy(self._state)
            new["boot_attempts"] += 1
            self._commit(new)
            self._fault("boot:counted")
            if new["boot_attempts"] > self.max_boot_attempts:
                return self._rollback(cid, "BOOT_ATTEMPTS_EXCEEDED")
        return self.active_slot

    def confirm_health(self, healthy: bool, correlation_id: str) -> Result:
        """FR-09 on success, FR-10 / SAF-05 on failure."""
        cid = correlation_id
        if self.update_state is not UpdateState.INSTALLED:
            return self._reject(cid, "confirm", Reason.INVALID_STATE)
        if healthy is not True:
            self._rollback(cid, "HEALTH_CHECK_FAILED")
            return Result(False, Reason.HEALTH_FAILED, cid)
        self._fault("confirm:before_commit")
        new = copy.deepcopy(self._state)
        version = new["slots"][new["active_slot"]]["version"]
        new["confirmed_slot"] = new["active_slot"]
        new["trusted_min_version"] = max(new["trusted_min_version"], version)
        new["update_state"] = UpdateState.CONFIRMED.value
        new["staged_version"] = None
        new["boot_attempts"] = 0
        new["last_correlation_id"] = cid
        self._commit(new)
        self._fault("confirm:committed")
        self._event(cid, "update_state", "CONFIRMED", version=version,
                    slot=new["active_slot"])
        return Result(True, Reason.OK, cid)

    def watchdog(self, seconds_since_activation: float, correlation_id: str) -> bool:
        """SAF-05: roll back when confirmation does not arrive in time. Returns True if rolled back."""
        if (self.update_state is UpdateState.INSTALLED
                and seconds_since_activation >= self.health_timeout_s):
            self._rollback(correlation_id, "HEALTH_TIMEOUT")
            return True
        return False

    def _rollback(self, cid: str, cause: str) -> str:
        self._fault("rollback:before_commit")
        new = copy.deepcopy(self._state)
        failed_version = new["slots"][new["active_slot"]]["version"] if new["slots"][new["active_slot"]] else None
        new["active_slot"] = new["confirmed_slot"]
        new["update_state"] = UpdateState.ROLLED_BACK.value
        new["boot_attempts"] = 0
        new["staged_version"] = None
        new["last_correlation_id"] = cid
        self._commit(new)
        self._fault("rollback:committed")
        self._event(cid, "update_state", "ROLLED_BACK", cause=cause,
                    failed_version=failed_version, slot=new["active_slot"])
        return new["active_slot"]

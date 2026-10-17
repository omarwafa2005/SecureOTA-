"""Controlled test bench: two ECUs, a gateway, fake clocks, an artifact repo
and a fault injector. TEST AND SIMULATION ONLY.

All keys are generated in memory for each run and never written to disk, so
no private key can end up in source control (SR-10).
"""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from .audit import AuditLog, new_correlation_id
from .ecu import Ecu, SimulatedPowerLoss, sha256_hex
from .gateway import Gateway
from .metadata import sign_envelope
from .safety import SafetyPolicy, VehicleConditions

VEHICLE_ID = "VIN-SIM-0001"
CAMPAIGN_ID = "CMP-2026-001"
ECU_HW = {"ECU-A": "HW-A-REV2", "ECU-B": "HW-B-REV1"}   # primary, secondary
SAFE = VehicleConditions()


class FakeClock:
    def __init__(self, start: float = 0.0):
        self.now = float(start)

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


@dataclass
class Signer:
    key_id: str
    private: Ed25519PrivateKey

    @classmethod
    def generate(cls, key_id: str) -> "Signer":
        return cls(key_id, Ed25519PrivateKey.generate())

    @property
    def public(self):
        return self.private.public_key()

    def sign(self, payload: dict) -> dict:
        return sign_envelope(payload, self.private, self.key_id)


def firmware(ecu_id: str, version: int, size: int = 8192) -> bytes:
    """Deterministic fake firmware image."""
    header = f"FW|{ecu_id}|v{version}|".encode()
    block = hashlib.sha256(header).digest()
    return (header + block * (size // len(block) + 1))[:size]


class ArtifactRepo:
    """Simulated artifact repository and transport."""

    def __init__(self):
        self.blobs: dict[str, bytes] = {}
        self.requests: list[tuple[str, str]] = []

    def put(self, data: bytes) -> str:
        artifact_id = "art-" + sha256_hex(data)[:16]
        self.blobs[artifact_id] = data
        return artifact_id

    def fetcher(self, *, clock: Optional[FakeClock] = None, chunk_size: int = 1024,
                delay_s: float = 0.0, disconnect_after: Optional[int] = None,
                serve: Optional[bytes] = None, endless: bool = False,
                stall_after: Optional[int] = None, stall_s: float = 0.0):
        def fetch(artifact_id: str, sha256: str):
            self.requests.append((artifact_id, sha256))
            if endless:
                while True:
                    if clock and delay_s:
                        clock.advance(delay_s)
                    yield b"\x00" * chunk_size
            data = serve if serve is not None else self.blobs[artifact_id]
            sent = 0
            stalled = False
            while sent < len(data):
                if disconnect_after is not None and sent >= disconnect_after:
                    raise ConnectionError("link lost")
                if clock and stall_after is not None and sent >= stall_after and not stalled:
                    clock.advance(stall_s)          # one long gap with no bytes
                    stalled = True
                if clock and delay_s:
                    clock.advance(delay_s)
                chunk = data[sent:sent + chunk_size]
                sent += len(chunk)
                yield chunk
        return fetch


class Bench:
    """Gateway + ECU-A (primary) + ECU-B (secondary), all persisted under `root`."""

    def __init__(self, root, *, policy: Optional[SafetyPolicy] = None, **gateway_kwargs):
        self.root = Path(root)
        self.clock = FakeClock(1_800_000_000)       # trusted wall clock (secure-time assumption)
        self.mono = FakeClock(0.0)                  # monotonic clock for timeouts
        self.audit = AuditLog(path=self.root / "audit.jsonl", clock=self.clock)
        self.policy = policy or SafetyPolicy()
        self.release = Signer.generate("release-key-1")
        self.vehicle_key = Signer.generate("vehicle-key-" + VEHICLE_ID)
        self.repo = ArtifactRepo()
        self.fail_at: set[str] = set()
        self.checkpoints_hit: list[str] = []
        self.revoked: set[str] = set()
        self.extra_trusted: dict = {}
        self.gateway_kwargs = gateway_kwargs
        self._metadata_version = 0
        self.root.mkdir(parents=True, exist_ok=True)
        for ecu_id, hw in ECU_HW.items():
            Ecu.provision(self.root / ecu_id, ecu_id=ecu_id, hardware_id=hw,
                          version=1, image=firmware(ecu_id, 1))
        self.restart()

    # ---------------------------------------------------------- fault model
    def fault(self, name: str) -> None:
        self.checkpoints_hit.append(name)
        if name in self.fail_at:
            self.fail_at.discard(name)
            raise SimulatedPowerLoss(name)

    def restart(self) -> None:
        """Model a power cycle: rebuild every object from what is on disk."""
        self.ecus = {ecu_id: Ecu(self.root / ecu_id, fault_hook=self.fault,
                                 audit=self.audit, policy=self.policy)
                     for ecu_id in ECU_HW}
        trusted = {self.release.key_id: self.release.public, **self.extra_trusted}
        self.gateway = Gateway(vehicle_id=VEHICLE_ID, ecus=self.ecus.values(),
                               trusted_keys=trusted, revoked_key_ids=self.revoked,
                               state_dir=self.root, manifest_key=self.vehicle_key.private,
                               manifest_key_id=self.vehicle_key.key_id,
                               clock=self.clock, monotonic=self.mono, audit=self.audit,
                               fault_hook=self.fault, **self.gateway_kwargs)

    # ------------------------------------------------------- release side
    def target(self, ecu_id: str = "ECU-A", version: int = 2, *,
               image: Optional[bytes] = None, signer: Optional[Signer] = None,
               **overrides) -> tuple[dict, bytes]:
        """Publish an image and return (signed envelope, image)."""
        image = image if image is not None else firmware(ecu_id, version)
        self._metadata_version += 1
        payload = {
            "artifact_id": self.repo.put(image),
            "campaign_id": CAMPAIGN_ID,
            "vehicle_id": VEHICLE_ID,
            "ecu_id": ecu_id,
            "hardware_id": ECU_HW.get(ecu_id, "HW-UNKNOWN"),
            "version": version,
            "metadata_version": self._metadata_version,
            "length": len(image),
            "sha256": sha256_hex(image),
            "expires_at": int(self.clock()) + 7 * 24 * 3600,
        }
        payload.update(overrides)
        return (signer or self.release).sign(payload), image

    def fetch(self, **kw):
        kw.setdefault("clock", self.mono)
        return self.repo.fetcher(**kw)

    # ------------------------------------------------------------ shortcuts
    def update(self, ecu_id: str = "ECU-A", version: int = 2, **kw):
        env, _ = self.target(ecu_id, version, **kw)
        return self.gateway.process_update(env, self.fetch())

    def install(self, ecu_id: str = "ECU-A", version: int = 2) -> None:
        """Full happy path to CONFIRMED; raises if any step fails."""
        cid = new_correlation_id()
        env, _ = self.target(ecu_id, version)
        steps = [self.gateway.process_update(env, self.fetch(), cid),
                 self.gateway.activate(ecu_id, SAFE, cid)]
        self.ecus[ecu_id].boot(cid)
        steps.append(self.ecus[ecu_id].confirm_health(True, cid))
        for r in steps:
            if not r.ok:
                raise AssertionError(f"install step failed: {r}")

    def snapshot(self) -> dict:
        return {ecu_id: ecu.snapshot() for ecu_id, ecu in self.ecus.items()}

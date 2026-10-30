"""Simulated signing environment (S3-T2; trust boundary TB-3).

The signing service holds private keys and is the only component that uses
them. The online backend never sees key material; it asks the service to sign
and the service decides whether the request is allowed:

  * a release key signs target metadata only for a release in state APPROVED
    whose approver differs from its creator (SR-15, SR-18, threat K-01)
  * a key signs only for its own role (SR-17, threat K-04)
  * every signature is recorded in a usage log so misuse is detectable

Private keys are generated in memory for tests. When loaded from disk they
must live outside the source tree (SR-10) and are stored encrypted with a
passphrase taken from the environment, never from a file in the repository.
"""
from __future__ import annotations

import os
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from vehicle.metadata import sign_envelope

from .keys import ROLES, make_keyset, sign_keyset

PASSPHRASE_ENV = "SECUREOTA_KEY_PASSPHRASE"


class SigningRefused(Exception):
    """The request is not allowed. `code` is a stable, non-sensitive category."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class KeyLocationError(Exception):
    """A private key path is inside the source tree (SR-10)."""


@dataclass
class _Key:
    role: str
    private: Ed25519PrivateKey


def _inside(path: Path, root: Path) -> bool:
    try:
        path.resolve().relative_to(root.resolve())
        return True
    except ValueError:
        return False


class SigningService:
    def __init__(self, clock: Callable[[], float] = time.time):
        self._keys: dict[str, _Key] = {}
        self._clock = clock
        self.usage_log: list[dict] = []

    # --------------------------------------------------------------- keys
    def generate(self, key_id: str, role: str) -> None:
        if role not in ROLES:
            raise ValueError("unknown role")
        if key_id in self._keys:
            raise ValueError("duplicate key id")
        self._keys[key_id] = _Key(role, Ed25519PrivateKey.generate())

    def public(self, key_id: str):
        return self._keys[key_id].private.public_key()

    def key_ids(self, role: str) -> list[str]:
        return sorted(k for k, v in self._keys.items() if v.role == role)

    def export_key(self, key_id: str, key_dir, *, repo_root) -> Path:
        """Write one encrypted PKCS#8 private key to key_dir (outside the repo)."""
        key_dir = Path(key_dir)
        if _inside(key_dir, Path(repo_root)):
            raise KeyLocationError("private keys must be stored outside the source tree")
        passphrase = os.environ.get(PASSPHRASE_ENV)
        if not passphrase:
            raise KeyLocationError(f"set {PASSPHRASE_ENV} to encrypt exported keys")
        key = self._keys[key_id]
        data = key.private.private_bytes(
            serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
            serialization.BestAvailableEncryption(passphrase.encode()))
        key_dir.mkdir(parents=True, exist_ok=True)
        path = key_dir / f"{key_id}.{key.role}.pem"
        path.write_bytes(data)
        return path

    def load_key(self, path, *, repo_root) -> str:
        path = Path(path)
        if _inside(path, Path(repo_root)):
            raise KeyLocationError("private keys must be stored outside the source tree")
        passphrase = os.environ.get(PASSPHRASE_ENV)
        if not passphrase:
            raise KeyLocationError(f"set {PASSPHRASE_ENV} to decrypt keys")
        key_id, role, _ext = path.name.rsplit(".", 2)
        private = serialization.load_pem_private_key(path.read_bytes(), passphrase.encode())
        if not isinstance(private, Ed25519PrivateKey) or role not in ROLES:
            raise ValueError("unsupported key file")
        self._keys[key_id] = _Key(role, private)
        return key_id

    # ------------------------------------------------------------ signing
    def _use(self, key_id: str, role: str, purpose: str, subject: str):
        key = self._keys.get(key_id)
        if key is None:
            raise SigningRefused("UNKNOWN_KEY")
        if key.role != role:
            self.usage_log.append({"time": self._clock(), "key_id": key_id, "purpose": purpose,
                                   "subject": subject, "outcome": "REFUSED_WRONG_ROLE"})
            raise SigningRefused("WRONG_KEY_ROLE")
        self.usage_log.append({"time": self._clock(), "key_id": key_id, "purpose": purpose,
                               "subject": subject, "outcome": "SIGNED"})
        return key.private

    def sign_target(self, payload: dict, release: dict, key_id: str) -> dict:
        """Sign per-vehicle target metadata for an approved release (SR-15, SR-18)."""
        rid = str(release.get("release_id"))
        if release.get("state") != "APPROVED" or not release.get("approved_by"):
            self.usage_log.append({"time": self._clock(), "key_id": key_id, "purpose": "target",
                                   "subject": rid, "outcome": "REFUSED_NOT_APPROVED"})
            raise SigningRefused("RELEASE_NOT_APPROVED")
        if release["approved_by"] == release.get("created_by"):
            self.usage_log.append({"time": self._clock(), "key_id": key_id, "purpose": "target",
                                   "subject": rid, "outcome": "REFUSED_SELF_APPROVAL"})
            raise SigningRefused("SEPARATION_OF_DUTIES")
        for field in ("ecu_id", "hardware_id", "version", "sha256", "length"):
            if payload.get(field) != release.get(field):
                raise SigningRefused("PAYLOAD_DIFFERS_FROM_RELEASE")
        private = self._use(key_id, "release", "target", rid)
        return sign_envelope(payload, private, key_id)

    def sign_keyset(self, *, version: int, expires_at: int, include: dict, revoked=(),
                    root_key_id: str) -> dict:
        """include: {key_id: role} of keys held here; returns a root-signed key set."""
        keys = {kid: (role, self.public(kid)) for kid, role in include.items()}
        private = self._use(root_key_id, "root", "keyset", f"v{version}")
        return sign_keyset(make_keyset(version=version, expires_at=expires_at, keys=keys,
                                       revoked=revoked), private, root_key_id)

    def provision_vehicle_key(self, key_id: str) -> Ed25519PrivateKey:
        """Hand a vehicle-role key to the simulated vehicle (factory provisioning only)."""
        key = self._keys.get(key_id)
        if key is None or key.role != "vehicle":
            raise SigningRefused("WRONG_KEY_ROLE")
        return key.private

"""Key roles and the root-signed trusted key set (Student 3, S3-T2).

Three key roles, each authorized for exactly one purpose (SR-17):

  root     offline; signs only the trusted key set; public key provisioned at
           the factory and never delivered over the network
  release  signs target metadata for approved releases
  vehicle  one per vehicle; signs the vehicle version manifest

The vehicle never trusts a key because a server says so. It trusts a key only
when it appears in a key set that verifies under the provisioned root key and
whose version is higher than the one it already holds (SR-16, threat K-02).
Rotation and revocation are both "publish a new key set version".

Ed25519 comes from the `cryptography` library; nothing here is a custom
primitive (working rule, Section 1).
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Mapping, Optional

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from vehicle.ecu import atomic_write
from vehicle.errors import Reason
from vehicle.metadata import sign_envelope, verify_envelope

ROLES = ("root", "release", "vehicle")
KEYSET_FIELDS = {"type", "version", "expires_at", "keys", "revoked"}
KEY_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{2,63}$")
PUBLIC_HEX_RE = re.compile(r"^[0-9a-f]{64}$")


def public_hex(public_key: Ed25519PublicKey) -> str:
    return public_key.public_bytes(serialization.Encoding.Raw,
                                   serialization.PublicFormat.Raw).hex()


def load_public(hex_value: str) -> Ed25519PublicKey:
    return Ed25519PublicKey.from_public_bytes(bytes.fromhex(hex_value))


def make_keyset(*, version: int, expires_at: int, keys: Mapping[str, tuple[str, Ed25519PublicKey]],
                revoked=()) -> dict:
    """keys: {key_id: (role, public_key)}. Returns the unsigned key set payload."""
    return {"type": "keyset", "version": version, "expires_at": expires_at,
            "keys": {kid: {"role": role, "public": public_hex(pub)}
                     for kid, (role, pub) in sorted(keys.items())},
            "revoked": sorted(revoked)}


def sign_keyset(payload: dict, root_private, root_key_id: str) -> dict:
    return sign_envelope(payload, root_private, root_key_id)


def _validate_keyset(p) -> bool:
    if not isinstance(p, dict) or set(p) != KEYSET_FIELDS or p["type"] != "keyset":
        return False
    for name in ("version", "expires_at"):
        if isinstance(p[name], bool) or not isinstance(p[name], int) or p[name] < 1:
            return False
    if not isinstance(p["keys"], dict) or not isinstance(p["revoked"], list):
        return False
    for kid, entry in p["keys"].items():
        if (not KEY_ID_RE.match(kid) or not isinstance(entry, dict)
                or set(entry) != {"role", "public"} or entry["role"] not in ROLES
                or entry["role"] == "root"            # root rotation is out of scope (ASM-07)
                or not isinstance(entry["public"], str)
                or not PUBLIC_HEX_RE.match(entry["public"])):
            return False
    return all(isinstance(k, str) and KEY_ID_RE.match(k) for k in p["revoked"])


class TrustStore:
    """Vehicle-side trusted key store, persisted atomically under `state_dir`."""

    STATE_FILE = "trust_store.json"

    def __init__(self, *, root_key_id: str, root_public: Ed25519PublicKey, state_dir,
                 clock=None):
        self.root_key_id = root_key_id
        self._root = {root_key_id: root_public}
        self._clock = clock
        self._path = Path(state_dir) / self.STATE_FILE
        self._keyset: Optional[dict] = None
        if self._path.exists():
            stored = json.loads(self._path.read_text(encoding="utf-8"))
            # Re-verify on load: the stored file is only trusted if root signed it.
            reason, payload = verify_envelope(stored, self._root)
            if reason is None and _validate_keyset(payload):
                self._keyset = payload

    @property
    def version(self) -> int:
        return self._keyset["version"] if self._keyset else 0

    def apply(self, envelope) -> Optional[Reason]:
        """Accept a new key set (rotation or revocation). Returns None or a reason."""
        reason, payload = verify_envelope(envelope, self._root)
        if reason:
            return reason
        if not _validate_keyset(payload):
            return Reason.MALFORMED_METADATA
        if payload["version"] <= self.version:
            return Reason.REPLAYED_METADATA                       # K-02 key set rollback
        if self._clock is not None and payload["expires_at"] <= self._clock():
            return Reason.EXPIRED_METADATA
        atomic_write(self._path, json.dumps(envelope, sort_keys=True).encode())
        self._keyset = payload
        return None

    def keys_for(self, role: str) -> dict[str, Ed25519PublicKey]:
        """Non-revoked public keys authorized for `role` (SR-17)."""
        if role not in ROLES:
            raise ValueError("unknown role")
        if not self._keyset:
            return {}
        revoked = set(self._keyset["revoked"])
        return {kid: load_public(e["public"]) for kid, e in self._keyset["keys"].items()
                if e["role"] == role and kid not in revoked}

    @property
    def revoked(self) -> frozenset:
        return frozenset(self._keyset["revoked"]) if self._keyset else frozenset()

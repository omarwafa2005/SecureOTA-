"""Signed target metadata: envelope verification and field validation.

Signatures use Ed25519 from the `cryptography` library. No cryptographic
primitive is designed here (working rule, Section 1). The envelope format is
a Phase 2 placeholder; the final metadata design (Uptane/TUF-informed) is a
Phase 3 decision owned by S3.

Envelope:   {"signed": {...target fields...}, "key_id": str, "sig": hex}
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Mapping, Optional

from cryptography.exceptions import InvalidSignature

from .errors import Reason

SHA256_RE = re.compile(r"^[0-9a-f]{64}$")

# Every field is mandatory; unknown fields are rejected (strict parsing).
TARGET_FIELDS: dict[str, type] = {
    "artifact_id": str,
    "campaign_id": str,
    "vehicle_id": str,
    "ecu_id": str,
    "hardware_id": str,
    "version": int,
    "metadata_version": int,
    "length": int,
    "sha256": str,
    "expires_at": int,
}


def canonical_bytes(obj) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode("ascii")


def payload_digest(payload: Mapping) -> str:
    return hashlib.sha256(canonical_bytes(payload)).hexdigest()


def sign_envelope(payload: Mapping, private_key, key_id: str) -> dict:
    """Signing belongs to the backend release process; used here by the test bench."""
    return {"signed": dict(payload), "key_id": key_id,
            "sig": private_key.sign(canonical_bytes(payload)).hex()}


def verify_envelope(envelope, trusted_keys: Mapping, revoked_key_ids=frozenset()
                    ) -> tuple[Optional[Reason], Optional[dict]]:
    """SR-03 / SR-04. Returns (None, payload) or (reason, None)."""
    if not isinstance(envelope, dict) or set(envelope) != {"signed", "key_id", "sig"}:
        return Reason.MALFORMED_METADATA, None
    payload, key_id, sig_hex = envelope["signed"], envelope["key_id"], envelope["sig"]
    if not isinstance(payload, dict) or not isinstance(key_id, str) or not isinstance(sig_hex, str):
        return Reason.MALFORMED_METADATA, None
    if key_id in revoked_key_ids or key_id not in trusted_keys:
        return Reason.UNTRUSTED_KEY, None
    try:
        signature = bytes.fromhex(sig_hex)
        data = canonical_bytes(payload)
    except (ValueError, TypeError):
        return Reason.MALFORMED_METADATA, None
    try:
        trusted_keys[key_id].verify(signature, data)
    except (InvalidSignature, ValueError):
        return Reason.BAD_SIGNATURE, None
    return None, payload


def validate_target(payload: Mapping) -> Optional[Reason]:
    if set(payload) != set(TARGET_FIELDS):
        return Reason.MALFORMED_METADATA
    for name, typ in TARGET_FIELDS.items():
        value = payload[name]
        if isinstance(value, bool) or not isinstance(value, typ):
            return Reason.MALFORMED_METADATA
        if typ is str and not value:
            return Reason.MALFORMED_METADATA
    if not SHA256_RE.match(payload["sha256"]):
        return Reason.MALFORMED_METADATA
    if payload["version"] < 0 or payload["metadata_version"] < 1 or payload["length"] < 1:
        return Reason.MALFORMED_METADATA
    return None

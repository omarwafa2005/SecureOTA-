"""Identities, roles and the authorization matrix (SR-08, SR-18, S2-T2).

Authentication is a simulated bearer token. Only SHA-256 hashes of tokens are
held, and comparison is constant-time. The authorization matrix below is the
single source for docs/generated/authorization_matrix.md.
"""
from __future__ import annotations

import hashlib
import hmac
from dataclasses import dataclass, field
from typing import Optional

from .errors import ApiError

ROLES = ("registrar", "release_creator", "release_approver", "campaign_operator",
         "auditor", "vehicle")

# action -> roles allowed to perform it. Anything not listed is denied.
AUTHZ_MATRIX: dict[str, tuple[str, ...]] = {
    "register_vehicle": ("registrar",),
    "upload_artifact": ("release_creator",),
    "create_release": ("release_creator",),
    "approve_release": ("release_approver",),        # and approver != creator (SR-18)
    "create_campaign": ("campaign_operator",),
    "start_campaign": ("campaign_operator",),
    "pause_campaign": ("campaign_operator",),
    "view_status": ("campaign_operator", "auditor"),
    "query_audit": ("auditor",),
    "get_instructions": ("vehicle",),                # own vehicle_id only
    "download_artifact": ("vehicle",),
    "report_event": ("vehicle",),                    # own vehicle_id only
    "submit_manifest": ("vehicle",),                 # own vehicle_id only
}

# Actions that change backend state or expose fleet data; each one is audited (SR-09).
PRIVILEGED = set(AUTHZ_MATRIX)


@dataclass(frozen=True)
class Principal:
    name: str
    roles: frozenset = field(default_factory=frozenset)
    vehicle_id: Optional[str] = None


ANONYMOUS = Principal("anonymous")


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


class Authenticator:
    def __init__(self):
        self._by_hash: dict[str, Principal] = {}

    def add(self, token: str, principal: Principal) -> None:
        if len(token) < 24:
            raise ValueError("token too short")
        for role in principal.roles:
            if role not in ROLES:
                raise ValueError("unknown role")
        if "vehicle" in principal.roles and not principal.vehicle_id:
            raise ValueError("vehicle identity needs a vehicle_id")
        self._by_hash[_hash(token)] = principal

    def authenticate(self, token: Optional[str]) -> Principal:
        if not token:
            raise ApiError("UNAUTHENTICATED")
        digest = _hash(token)
        for known, principal in self._by_hash.items():
            if hmac.compare_digest(known, digest):
                return principal
        raise ApiError("UNAUTHENTICATED")


def allowed(principal: Principal, action: str) -> bool:
    return bool(principal.roles.intersection(AUTHZ_MATRIX.get(action, ())))

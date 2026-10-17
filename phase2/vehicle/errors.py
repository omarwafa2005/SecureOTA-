"""Stable result and rejection categories for the vehicle side.

Every rejection returns a stable reason code plus a correlation ID and
nothing else (US-02, SR-11). Internal diagnostics are short codes, never
file paths, key material or stack traces.
"""
from __future__ import annotations

from dataclasses import dataclass
from enum import Enum


class Reason(str, Enum):
    OK = "OK"
    ALREADY_APPLIED = "ALREADY_APPLIED"            # idempotent repeat (FR-11)
    MALFORMED_METADATA = "MALFORMED_METADATA"
    UNTRUSTED_KEY = "UNTRUSTED_KEY"                # SR-04
    BAD_SIGNATURE = "BAD_SIGNATURE"                # SR-03
    EXPIRED_METADATA = "EXPIRED_METADATA"          # SR-07 / T-07
    REPLAYED_METADATA = "REPLAYED_METADATA"        # SR-07 / T-03
    INCONSISTENT_METADATA = "INCONSISTENT_METADATA"  # SR-07 / T-06
    WRONG_TARGET = "WRONG_TARGET"                  # SR-05 / T-05
    ROLLBACK_REJECTED = "ROLLBACK_REJECTED"        # SR-06 / T-04
    ALREADY_INSTALLED = "ALREADY_INSTALLED"
    ARTIFACT_TOO_LARGE = "ARTIFACT_TOO_LARGE"      # SR-12 / T-08
    LENGTH_MISMATCH = "LENGTH_MISMATCH"            # SR-12 / T-08
    DIGEST_MISMATCH = "DIGEST_MISMATCH"            # SR-02 / T-01
    DOWNLOAD_TIMEOUT = "DOWNLOAD_TIMEOUT"          # NFR-04 / T-09
    NETWORK_ERROR = "NETWORK_ERROR"                # F-01
    ACTIVATION_POSTPONED = "ACTIVATION_POSTPONED"  # SAF-03 / SAF-04
    INVALID_STATE = "INVALID_STATE"                # SAF-10
    STORAGE_ERROR = "STORAGE_ERROR"                # SAF-07
    HEALTH_FAILED = "HEALTH_FAILED"                # SAF-05


@dataclass(frozen=True)
class Result:
    ok: bool
    reason: Reason
    correlation_id: str
    detail: tuple = ()  # short internal codes only, e.g. ("SPEED_NONZERO",)

    def public(self) -> dict:
        """The only form a result may take outside the vehicle (US-02)."""
        if self.ok:
            status = "OK"
        elif self.reason is Reason.ACTIVATION_POSTPONED:
            status = "POSTPONED"
        else:
            status = "REJECTED"
        return {"status": status, "reason": self.reason.value,
                "correlation_id": self.correlation_id}

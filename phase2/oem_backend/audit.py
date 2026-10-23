"""Append-only, hash-chained audit trail (SR-09, SR-14, threat B-05).

Each event stores the hash of the previous event. Changing or deleting any
event breaks the chain, and `verify()` reports the first broken sequence
number. Someone with full write access could rebuild the whole chain, so the
head hash is also exported (`head()`) to a separate location; checking against
that anchor detects a rebuilt chain (residual risk recorded for B-05).

Events never carry secrets: field names that look like credentials are
refused at write time (NFR-05).
"""
from __future__ import annotations

import hashlib
import json
import time
from typing import Callable, Optional

GENESIS = "0" * 64
FORBIDDEN_FIELDS = ("token", "password", "secret", "private", "credential", "passphrase")
REQUIRED = ("seq", "time", "actor", "action", "object", "outcome", "correlation_id")


def _digest(event: dict) -> str:
    body = {k: v for k, v in event.items() if k != "hash"}
    return hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"))
                          .encode()).hexdigest()


class AuditTrail:
    def __init__(self, clock: Callable[[], float] = time.time):
        self._events: list[dict] = []
        self._clock = clock

    def record(self, *, actor: str, action: str, obj: str, outcome: str,
               correlation_id: str, **fields) -> dict:
        if not correlation_id:
            raise ValueError("audit event needs a correlation_id (NFR-02)")
        for name in fields:
            if any(bad in name.lower() for bad in FORBIDDEN_FIELDS):
                raise ValueError("audit fields must not carry secrets (NFR-05)")
        event = {"seq": len(self._events) + 1, "time": self._clock(), "actor": actor,
                 "action": action, "object": obj, "outcome": outcome,
                 "correlation_id": correlation_id, **fields,
                 "prev_hash": self._events[-1]["hash"] if self._events else GENESIS}
        event["hash"] = _digest(event)
        self._events.append(event)
        return dict(event)

    def head(self) -> str:
        return self._events[-1]["hash"] if self._events else GENESIS

    def verify(self, anchor: Optional[str] = None) -> tuple[bool, Optional[int]]:
        """(True, None) if intact; otherwise (False, first bad seq)."""
        prev = GENESIS
        for index, event in enumerate(self._events, start=1):
            if (event.get("seq") != index or event.get("prev_hash") != prev
                    or event.get("hash") != _digest(event)):
                return False, index
            prev = event["hash"]
        if anchor is not None and anchor != prev:
            return False, len(self._events)
        return True, None

    def query(self, **match) -> list[dict]:
        return [dict(e) for e in self._events if all(e.get(k) == v for k, v in match.items())]

    @property
    def events(self) -> list[dict]:
        return [dict(e) for e in self._events]

    # Test-bench access to the raw store, used only to simulate tampering (B-05).
    @property
    def _raw(self) -> list[dict]:
        return self._events

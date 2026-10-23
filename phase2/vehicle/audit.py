"""Correlated, append-only audit events for the vehicle side (FR-06, NFR-02).

Events carry correlation_id, component, action and outcome plus small
non-secret fields (ecu_id, version, reason). Student 2 owns the backend
audit pipeline; this log is the vehicle-side evidence source for it.
"""
from __future__ import annotations

import json
import time
import uuid
from pathlib import Path
from typing import Callable, Optional


def new_correlation_id() -> str:
    return uuid.uuid4().hex


class AuditLog:
    def __init__(self, path: Optional[Path] = None, clock: Callable[[], float] = time.time):
        self._events: list[dict] = []
        self._path = Path(path) if path else None
        self._clock = clock

    def record(self, correlation_id: str, component: str, action: str,
               outcome: str, **fields) -> dict:
        if not correlation_id:
            raise ValueError("every vehicle event needs a correlation_id (NFR-02)")
        event = {"time": self._clock(), "correlation_id": correlation_id,
                 "component": component, "action": action, "outcome": outcome}
        event.update(fields)
        self._events.append(event)
        if self._path is not None:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps(event, sort_keys=True) + "\n")
        return event

    @property
    def events(self) -> list[dict]:
        return list(self._events)

    def find(self, **match) -> list[dict]:
        return [e for e in self._events
                if all(e.get(k) == v for k, v in match.items())]

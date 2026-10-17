"""Simulated vehicle conditions and the activation safety policy (SAF-03, SAF-04).

Unsafe or invalid inputs block activation; they never block evidence
collection (S1-T3 completion check). Missing, negative or non-finite values
are treated as unsafe (threat V-05).
"""
from __future__ import annotations

import math
from dataclasses import dataclass


def _finite_number(x) -> bool:
    return isinstance(x, (int, float)) and not isinstance(x, bool) and math.isfinite(x)


@dataclass(frozen=True)
class VehicleConditions:
    speed_kph: float = 0.0
    ignition: str = "ON"
    battery_v: float = 12.6
    gear: str = "P"
    diagnostic_session: bool = False


@dataclass(frozen=True)
class SafetyPolicy:
    min_battery_v: float = 12.0             # SAF-04 threshold (configurable)
    allowed_ignition: frozenset = frozenset({"ON"})
    require_park: bool = True

    def blocking_reasons(self, c: VehicleConditions) -> tuple[str, ...]:
        reasons = []
        if not _finite_number(c.speed_kph) or c.speed_kph != 0:
            reasons.append("SPEED_NONZERO")              # SAF-03
        if not _finite_number(c.battery_v) or c.battery_v < self.min_battery_v:
            reasons.append("BATTERY_LOW")                # SAF-04
        if c.ignition not in self.allowed_ignition:
            reasons.append("IGNITION_STATE")
        if self.require_park and c.gear != "P":
            reasons.append("NOT_IN_PARK")
        if c.diagnostic_session is not False:
            reasons.append("DIAGNOSTIC_SESSION_ACTIVE")
        return tuple(reasons)

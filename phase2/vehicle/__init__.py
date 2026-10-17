"""SecureOTA-V vehicle side (Student 1, Merged Phase 2).

Executable specification of the gateway and ECU behaviour defined in
docs/student1_vehicle_spec.md. Simulation only; not production code.
"""
from .audit import AuditLog, new_correlation_id
from .ecu import CHECKPOINTS, Ecu, SimulatedPowerLoss, UpdateState
from .errors import Reason, Result
from .gateway import Gateway, verify_manifest
from .safety import SafetyPolicy, VehicleConditions

__all__ = ["AuditLog", "new_correlation_id", "CHECKPOINTS", "Ecu", "SimulatedPowerLoss",
           "UpdateState", "Reason", "Result", "Gateway", "verify_manifest",
           "SafetyPolicy", "VehicleConditions"]

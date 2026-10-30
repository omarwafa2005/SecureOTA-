"""SecureOTA-V OEM backend (S2, Merged Phase 2).

Feasibility prototype for docs/backend_spec.md: domain model,
authorization matrix, audit trail and API behavior. In-memory storage;
not production code.
"""
from .audit import AuditTrail
from .auth import AUTHZ_MATRIX, Authenticator, Principal
from .errors import ApiError
from .service import STATUS_LABELS, BackendService, dependency_order

__all__ = ["AuditTrail", "AUTHZ_MATRIX", "Authenticator", "Principal", "ApiError",
           "STATUS_LABELS", "BackendService", "dependency_order"]

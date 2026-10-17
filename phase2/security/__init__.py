"""SecureOTA-V security and key lifecycle (Student 3, Merged Phase 2).

Feasibility prototype for the key-lifecycle concept in
docs/student3_security_spec.md. Simulation only; no hardware key storage.
"""
from .keys import ROLES, TrustStore, load_public, make_keyset, public_hex, sign_keyset
from .signing import KeyLocationError, SigningRefused, SigningService

__all__ = ["ROLES", "TrustStore", "load_public", "make_keyset", "public_hex", "sign_keyset",
           "KeyLocationError", "SigningRefused", "SigningService"]

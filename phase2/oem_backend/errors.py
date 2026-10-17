"""Stable external error categories (SR-11, US-02).

An ApiError carries a category, an optional stable sub-code and, for
planner errors only, a diagnostic built from public identifiers (ECU IDs).
The message shown to a caller is fixed per category, so no file path, stack
trace, key material or internal identifier can reach an external error.
"""
from __future__ import annotations

CATEGORIES = {
    "VALIDATION_FAILED": (422, "The request is invalid."),
    "UNAUTHENTICATED": (401, "Authentication is required."),
    "FORBIDDEN": (403, "The caller is not allowed to perform this action."),
    "NOT_FOUND": (404, "The requested object does not exist."),
    "CONFLICT": (409, "The request conflicts with the current state."),
    "PAYLOAD_TOO_LARGE": (413, "The request body is too large."),
    "INTERNAL": (500, "Internal error."),
}


class ApiError(Exception):
    def __init__(self, category: str, code: str = "", diagnostic: str = ""):
        if category not in CATEGORIES:
            raise ValueError("unknown error category")
        super().__init__(f"{category}:{code}")
        self.category = category
        self.code = code or category
        self.diagnostic = diagnostic

    @property
    def status(self) -> int:
        return CATEGORIES[self.category][0]

    def public(self, correlation_id: str) -> dict:
        body = {"error": self.category, "code": self.code,
                "message": CATEGORIES[self.category][1], "correlation_id": correlation_id}
        if self.diagnostic:
            body["diagnostic"] = self.diagnostic
        return body

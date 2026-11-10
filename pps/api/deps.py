"""Shared API dependencies: core access, authentication and role checks (PPS-SR-004).

Bridges the auth module (PR 10), which works with ``Principal`` objects and raises typed
errors, to the API, which passes ``{"username", "role"}`` dicts and answers with the
``{error: {code, message}}`` envelope.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from fastapi import Depends, Request

from ..auth import (
    AuthenticationError,
    AuthError,
    AuthorizationError,
    LastAdminError,
    LockedOutError,
    Principal,
    Role,
    UserNotFoundError,
    UserValidationError,
    require_role,
)
from ..core import Core


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


# Most specific first: LockedOutError is not an AuthenticationError, but keep the order explicit.
_AUTH_ERRORS: list[tuple[type[AuthError], int, str]] = [
    (LockedOutError, 429, "LOCKED_OUT"),
    (AuthenticationError, 401, "UNAUTHENTICATED"),
    (AuthorizationError, 403, "FORBIDDEN"),
    (UserNotFoundError, 404, "NOT_FOUND"),
    (LastAdminError, 409, "LAST_ADMIN"),
    (UserValidationError, 400, "BAD_REQUEST"),
]


def auth_error_status(exc: AuthError) -> tuple[int, str]:
    """HTTP status and error code for an auth module error."""
    for exc_type, status, code in _AUTH_ERRORS:
        if isinstance(exc, exc_type):
            return status, code
    return 400, "AUTH_ERROR"


def get_core(request: Request) -> Core:
    return request.app.state.core


def bearer(request: Request) -> str | None:
    h = request.headers.get("authorization", "")
    return h[7:] if h.lower().startswith("bearer ") else None


def user_dict(principal: Principal) -> dict[str, Any]:
    return {"username": principal.username, "role": principal.role.value}


def principal_of(user: dict[str, Any]) -> Principal:
    return Principal(user["username"], Role.parse(user["role"]))


def current_user(request: Request, core: Core = Depends(get_core)) -> dict[str, Any]:
    return user_dict(core.auth.authenticate_token(bearer(request)))


def require(min_role: str) -> Callable[..., dict[str, Any]]:
    """Dependency factory: deny by default unless the caller's role is at least `min_role`."""
    minimum = Role.parse(min_role)

    def dep(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
        require_role(principal_of(user), minimum)
        return user

    return dep


def remote_addr(request: Request) -> str:
    return request.client.host if request.client else "unknown"

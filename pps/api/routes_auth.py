"""Pairing, login and user management (PPS-F-050, PPS-F-061, PPS-SR-001, PPS-SR-004)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field

from ..auth import AuthenticationError
from ..core import Core
from .deps import ApiError, current_user, get_core, principal_of, require

router = APIRouter(tags=["auth"])


class PairIn(BaseModel):
    pin: str = Field(..., examples=["123456"])
    client_name: str = "browser"


class LoginIn(BaseModel):
    username: str
    password: str


class UserIn(BaseModel):
    username: str
    password: str
    role: str = "analyst"


class UserPatch(BaseModel):
    role: str | None = None
    active: bool | None = None
    password: str | None = None


@router.post("/pair")
def pair(body: PairIn, core: Core = Depends(get_core)) -> dict[str, Any]:
    try:
        token = core.auth.pair(body.pin, body.client_name)
    except AuthenticationError as exc:
        raise ApiError(401, "PIN_INVALID", "Invalid pairing PIN.") from exc
    return {"client_token": token}


@router.post("/auth/login")
def login(body: LoginIn, request: Request, core: Core = Depends(get_core)) -> dict[str, Any]:
    client_token = request.headers.get("x-pps-client")
    try:
        core.auth.validate_client(client_token)
    except AuthenticationError as exc:
        raise ApiError(401, "NOT_PAIRED", "This browser is not paired with the device.") from exc
    try:
        r = core.auth.login(body.username, body.password, client_token)
    except AuthenticationError as exc:
        raise ApiError(401, "INVALID_CREDENTIALS", "Invalid username or password.") from exc
    return {
        "access_token": r.access_token,
        "token_type": r.token_type,
        "expires_in": r.expires_in_s,
        "username": r.username,
        "role": r.role.value,
    }


@router.get("/auth/me")
def me(user: dict[str, Any] = Depends(current_user)) -> dict[str, Any]:
    return user


@router.get("/users")
def list_users(
    _: dict = Depends(require("admin")), core: Core = Depends(get_core)
) -> list[dict[str, Any]]:
    return core.storage.list_users()


@router.post("/users", status_code=201)
def create_user(
    body: UserIn, user: dict = Depends(require("admin")), core: Core = Depends(get_core)
) -> dict:
    core.auth.create_user(principal_of(user), body.username, body.password, body.role)
    return {"username": body.username.strip().lower(), "role": body.role.lower()}


@router.patch("/users/{username}")
def update_user(
    username: str,
    body: UserPatch,
    user: dict = Depends(require("admin")),
    core: Core = Depends(get_core),
) -> dict:
    if body.role is None and body.active is None and not body.password:
        raise ApiError(400, "BAD_REQUEST", "Nothing to change.")
    actor = principal_of(user)
    if body.role is not None:
        core.auth.set_role(actor, username, body.role)
    if body.active is not None:
        core.auth.set_active(actor, username, body.active)
    if body.password:
        core.auth.reset_password(actor, username, body.password)
    return {"ok": True}

"""FastAPI application factory."""

from __future__ import annotations

from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import FileResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles

from .. import __version__
from ..auth import AuthError, LockedOutError
from ..capture import CaptureError
from ..core import Core
from ..settings import Settings
from . import (
    routes_alerts,  # PPS-F-040..043
    routes_audit,  # PPS-SR-005
    routes_auth,  # PPS-F-050, F-061, SR-001, SR-004
    routes_capture,  # PPS-F-001..003, F-030/031, F-051/052
    routes_config,  # PPS-F-060
    routes_filters,  # PPS-F-020..023
    routes_health,  # PPS-F-062
)
from .deps import ApiError, auth_error_status

STATIC = Path(__file__).resolve().parent.parent / "static"
API = "/api/v1"

# One router per feature area; each feature PR adds its router here.
ROUTERS = [
    routes_auth.router,
    routes_capture.router,
    routes_filters.router,
    routes_alerts.router,
    routes_config.router,
    routes_audit.router,
    routes_health.router,
]


def _err(status: int, code: str, message: str) -> JSONResponse:
    return JSONResponse(status_code=status, content={"error": {"code": code, "message": message}})


def create_app(settings: Settings | None = None, pin: str | None = None) -> FastAPI:
    core = Core(settings or Settings(), pin=pin)

    @asynccontextmanager
    async def lifespan(_: FastAPI):
        yield
        core.close()

    app = FastAPI(
        title="Pocket Packet Sniffer",
        version=__version__,
        docs_url="/api/docs",
        openapi_url=f"{API}/openapi.json",
        lifespan=lifespan,
    )
    app.state.core = core

    for exc_type in (CaptureError, ApiError):

        @app.exception_handler(exc_type)
        async def _handle(_: Request, exc: Exception) -> JSONResponse:
            return _err(exc.status, exc.code, exc.message)  # type: ignore[attr-defined]

    @app.exception_handler(AuthError)
    async def _auth(_: Request, exc: AuthError) -> JSONResponse:
        status, code = auth_error_status(exc)
        resp = _err(status, code, str(exc))
        if isinstance(exc, LockedOutError):
            resp.headers["Retry-After"] = str(exc.retry_after_s)
        return resp

    for r in ROUTERS:
        app.include_router(r, prefix=API)

    @app.get(f"{API}/info")
    def info() -> dict:
        return {"name": "Pocket Packet Sniffer", "version": __version__}

    app.mount("/static", StaticFiles(directory=STATIC, check_dir=False), name="static")

    @app.get("/", include_in_schema=False)
    def index() -> Response:
        page = STATIC / "index.html"
        if not page.is_file():  # the dashboard is added in PR 13
            return _err(404, "NO_DASHBOARD", "Dashboard not installed; the API is at /api/v1.")
        return FileResponse(page)

    return app

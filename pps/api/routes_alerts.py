"""Alert history and acknowledgement (PPS-F-040..043)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from ..core import Core
from .deps import ApiError, get_core, require

router = APIRouter(tags=["alerts"])


@router.get("/alerts")
def list_alerts(
    since: float | None = None,
    type: str | None = None,
    session_id: str | None = None,
    limit: int = Query(200, ge=1, le=1000),
    _: dict = Depends(require("trainee")),
    core: Core = Depends(get_core),
) -> list:
    return core.storage.list_alerts(
        since=since, type_=type, session_id=session_id, limit=limit
    )


@router.post("/alerts/{alert_id}/ack")
def ack(
    alert_id: int, user: dict = Depends(require("analyst")), core: Core = Depends(get_core)
) -> dict:
    if not core.storage.ack_alert(alert_id):
        raise ApiError(404, "NOT_FOUND", "No such alert.")
    core.storage.audit(user["username"], "ALERT_ACK", {"alert_id": alert_id})
    return {"ok": True}

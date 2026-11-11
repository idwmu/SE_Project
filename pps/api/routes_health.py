"""Device health view (PPS-F-062) including storage status (PPS-F-034)."""

from __future__ import annotations

from fastapi import APIRouter, Depends

from ..core import Core
from ..health import health_snapshot
from .deps import get_core, require

router = APIRouter(tags=["health"])


@router.get("/device/health")
def health(_: dict = Depends(require("trainee")), core: Core = Depends(get_core)) -> dict:
    st = core.storage.storage_status(core.storage.get_config())
    return health_snapshot(st, core.capture.state, core.bus.subscriber_count, core.ws_dropped)

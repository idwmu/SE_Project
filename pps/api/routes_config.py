"""Configuration: interface defaults, limits, alert thresholds, storage quota (PPS-F-060)."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends

from ..core import Core
from ..settings import DEFAULT_CONFIG
from .deps import ApiError, get_core, require

router = APIRouter(tags=["config"])

INT_KEYS = {
    "max_duration_s": (0, 86400),
    "max_packets": (0, 10_000_000),
    "portscan_threshold": (3, 1000),
    "portscan_window_s": (1, 3600),
    "max_storage_mb": (10, 1_000_000),
    "low_space_warn_pct": (1, 90),
}


@router.get("/config")
def get_config(_: dict = Depends(require("trainee")), core: Core = Depends(get_core)) -> dict:
    return core.storage.get_config()


@router.put("/config")
def put_config(
    body: dict[str, Any], user: dict = Depends(require("admin")), core: Core = Depends(get_core)
) -> dict:
    clean: dict[str, Any] = {}
    for k, v in body.items():
        if k not in DEFAULT_CONFIG:
            raise ApiError(400, "BAD_KEY", f"Unknown setting {k!r}.")
        if k in INT_KEYS:
            lo, hi = INT_KEYS[k]
            # bool is an int subclass and int(2.9) truncates: accept whole numbers only
            if isinstance(v, bool) or (isinstance(v, float) and not v.is_integer()):
                raise ApiError(400, "BAD_VALUE", f"{k} must be a whole number.")
            try:
                v = int(v)
            except (TypeError, ValueError) as exc:
                raise ApiError(400, "BAD_VALUE", f"{k} must be a whole number.") from exc
            if not lo <= v <= hi:
                raise ApiError(400, "BAD_VALUE", f"{k} must be between {lo} and {hi}.")
        elif k == "arp_whitelist":
            if not isinstance(v, list) or not all(isinstance(x, str) and "=" in x for x in v):
                raise ApiError(400, "BAD_VALUE", "arp_whitelist entries must look like ip=mac.")
        else:
            v = str(v)
        clean[k] = v
    old = core.storage.get_config()
    cfg = core.storage.set_config(clean)
    changes = {k: {"from": old.get(k), "to": v} for k, v in clean.items() if old.get(k) != v}
    core.storage.audit(user["username"], "CONFIG_CHANGED", changes)
    return cfg

"""Filter validation and saved presets (PPS-F-020..023)."""

from __future__ import annotations

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ..bpf import BpfError, validate_bpf
from ..core import Core
from ..displayfilter import FilterError, compile_filter
from .deps import ApiError, get_core, require

router = APIRouter(tags=["filters"])


class ValidateIn(BaseModel):
    expression: str
    kind: str = "display"  # "display" | "bpf"


class PresetIn(BaseModel):
    expression: str


@router.post("/filters/validate")
def validate(body: ValidateIn, _: dict = Depends(require("trainee"))) -> dict:
    try:
        if body.kind == "bpf":
            checked = validate_bpf(body.expression)
            return {
                "valid": True,
                "checked": checked,
                "note": None
                if checked
                else "libpcap/Npcap not available here; checked at capture start.",
            }
        compile_filter(body.expression)
        return {"valid": True, "checked": True}
    except (FilterError, BpfError) as exc:
        return {"valid": False, "error": str(exc)}


@router.get("/filters/presets")
def presets(_: dict = Depends(require("trainee")), core: Core = Depends(get_core)) -> list:
    return core.storage.list_presets()


@router.put("/filters/presets/{name}")
def save_preset(
    name: str,
    body: PresetIn,
    user: dict = Depends(require("analyst")),
    core: Core = Depends(get_core),
) -> dict:
    try:
        compile_filter(body.expression)
    except FilterError as exc:
        raise ApiError(400, "FILTER_INVALID", str(exc)) from exc
    name = name.strip()
    if not name or len(name) > 60:
        raise ApiError(400, "BAD_NAME", "Preset name must be 1 to 60 characters.")
    core.storage.save_preset(name, body.expression, user["username"])
    return {"name": name, "expression": body.expression}


@router.delete("/filters/presets/{name}")
def delete_preset(
    name: str, _: dict = Depends(require("analyst")), core: Core = Depends(get_core)
) -> dict:
    if not core.storage.delete_preset(name):
        raise ApiError(404, "NOT_FOUND", "No such preset.")
    return {"ok": True}

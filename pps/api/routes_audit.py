"""Tamper-evident audit log (PPS-SR-005)."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Query

from ..core import Core
from .deps import get_core, require

router = APIRouter(tags=["audit"])


@router.get("/audit")
def audit(
    limit: int = Query(300, ge=1, le=2000),  # a negative LIMIT would make SQLite return every row
    _: dict = Depends(require("admin")),
    core: Core = Depends(get_core),
) -> dict:
    """The newest ``limit`` entries, plus whether the hash chain over *all* entries verifies."""
    return {
        "verification": core.storage.verify_audit(),
        "entries": core.storage.list_audit(limit),
    }

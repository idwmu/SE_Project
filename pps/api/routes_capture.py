"""Capture control, session export and the live WebSocket.

Requirements: PPS-F-001..003, F-030, F-031, F-051, F-052.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import Any

from fastapi import APIRouter, Depends, Query, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from pydantic import BaseModel
from scapy.utils import PcapReader

from ..auth import AuthError
from ..core import Core
from ..decode import decode
from ..displayfilter import FilterError, compile_filter
from ..interfaces import list_interfaces
from .deps import ApiError, auth_error_status, get_core, require

router = APIRouter(tags=["capture"])


class StartIn(BaseModel):
    source_type: str = "replay"  # "live" | "replay"
    source: str
    bpf: str = ""
    duration_s: int | None = None
    max_packets: int | None = None
    replay_speed: float = 1.0
    authorised: bool = False


@router.get("/interfaces")
def interfaces(_: dict = Depends(require("analyst"))) -> list[dict[str, Any]]:
    return [i.to_dict() for i in list_interfaces()]


@router.get("/replay-files")
def replay_files(
    _: dict = Depends(require("trainee")), core: Core = Depends(get_core)
) -> list[dict]:
    return core.capture.list_replay_files()


@router.post("/replay-files", status_code=201)
async def upload_replay(
    file: UploadFile, user: dict = Depends(require("analyst")), core: Core = Depends(get_core)
) -> dict:
    name = (file.filename or "").replace("\\", "/").split("/")[-1]
    if not name.endswith((".pcap", ".pcapng")):
        raise ApiError(400, "BAD_FILE", "Only .pcap or .pcapng files can be uploaded.")
    data = await file.read()
    if len(data) > 50 * 1024 * 1024:
        raise ApiError(413, "TOO_LARGE", "Replay files are limited to 50 MB.")
    (core.settings.replay_dir / name).write_bytes(data)
    core.storage.audit(user["username"], "REPLAY_UPLOADED", {"file": name, "bytes": len(data)})
    return {"name": name, "size": len(data)}


@router.get("/capture/status")
def status(_: dict = Depends(require("trainee")), core: Core = Depends(get_core)) -> dict:
    return core.capture.status()


@router.post("/captures", status_code=201)
def start(
    body: StartIn, user: dict = Depends(require("analyst")), core: Core = Depends(get_core)
) -> dict:
    st = core.capture.start(
        source_type=body.source_type,
        source=body.source,
        bpf=body.bpf,
        duration_s=body.duration_s,
        max_packets=body.max_packets,
        replay_speed=body.replay_speed,
        user=user["username"],
        authorised=body.authorised,
    )
    core.storage.audit(
        user["username"],
        "CAPTURE_START",
        {
            "session": st["session"]["id"] if st["session"] else None,
            "source": f"{body.source_type}:{body.source}",
            "bpf": body.bpf,
            "authorised": body.authorised,
        },
    )
    return st


@router.post("/captures/{session_id}/stop")
def stop(
    session_id: str, user: dict = Depends(require("analyst")), core: Core = Depends(get_core)
) -> dict:
    cur = core.capture.session
    if not cur or cur["id"] != session_id:
        raise ApiError(404, "NOT_FOUND", "That session is not running.")
    st = core.capture.stop(user=user["username"])
    core.storage.audit(user["username"], "CAPTURE_STOP", {"session": session_id})
    return st


@router.get("/captures")
def sessions(_: dict = Depends(require("trainee")), core: Core = Depends(get_core)) -> list[dict]:
    return core.storage.list_sessions()


def _session_file(core: Core, session_id: str):
    s = core.storage.get_session(session_id)
    path = core.storage.pcap_path(session_id) if s else None
    if not s or not path or not path.is_file():
        raise ApiError(404, "NOT_FOUND", "Session or capture file not found.")
    if s["status"] == "ACTIVE":
        raise ApiError(409, "CAPTURE_ACTIVE", "Stop the capture before exporting it.")
    return s, path


@router.get("/captures/{session_id}/pcap")
def export_pcap(
    session_id: str, user: dict = Depends(require("trainee")), core: Core = Depends(get_core)
):
    _, path = _session_file(core, session_id)
    core.storage.audit(user["username"], "CAPTURE_EXPORT", {"session": session_id})
    return FileResponse(
        path, media_type="application/vnd.tcpdump.pcap", filename=f"{session_id}.pcap"
    )


@router.get("/captures/{session_id}/packets")
def session_packets(
    session_id: str,
    filter: str = "",
    offset: int = 0,
    limit: int = Query(200, le=2000),
    _: dict = Depends(require("trainee")),
    core: Core = Depends(get_core),
) -> dict:
    """Search a stored session with a display filter (PPS-F-021, F-022)."""
    _, path = _session_file(core, session_id)
    try:
        pred = compile_filter(filter)
    except FilterError as exc:
        raise ApiError(400, "FILTER_INVALID", str(exc)) from exc
    matched, out, total = 0, [], 0
    with PcapReader(str(path)) as reader:
        for i, pkt in enumerate(reader, start=1):
            total += 1
            d = decode(pkt, i).to_dict()
            if pred(d):
                if matched >= offset and len(out) < limit:
                    out.append(d)
                matched += 1
    return {"total": total, "matched": matched, "offset": offset, "packets": out}


@router.delete("/captures/{session_id}")
def delete_session(
    session_id: str, user: dict = Depends(require("admin")), core: Core = Depends(get_core)
):
    _session_file(core, session_id)
    core.storage.delete_session(session_id)
    core.storage.audit(user["username"], "CAPTURE_DELETED", {"session": session_id})
    return {"ok": True}


@router.websocket("/ws/live")
async def live(ws: WebSocket, token: str = "", filter: str = "") -> None:
    """Pushes batched packets, stats, alerts and state every 250 ms (PPS-F-051, F-043)."""
    core: Core = ws.app.state.core
    await ws.accept()
    try:
        core.auth.authenticate_token(token or None)
    except AuthError as exc:
        _, code = auth_error_status(exc)
        await ws.send_json({"type": "error", "code": code, "message": str(exc)})
        await ws.close(code=4401)
        return
    state = {"pred": None, "filter": filter}
    try:
        state["pred"] = compile_filter(filter)
    except FilterError as exc:
        state["pred"] = compile_filter("")
        await ws.send_json({"type": "error", "code": "FILTER_INVALID", "message": str(exc)})

    sub = core.bus.subscribe(maxlen=5000)
    period = core.settings.ws_batch_ms / 1000

    async def receiver() -> None:
        while True:
            msg = await ws.receive_json()
            if "filter" in msg:
                try:
                    state["pred"] = compile_filter(msg["filter"])
                    state["filter"] = msg["filter"]
                    await ws.send_json({"type": "filter_ok", "filter": msg["filter"]})
                except FilterError as exc:
                    await ws.send_json(
                        {"type": "error", "code": "FILTER_INVALID", "message": str(exc)}
                    )

    recv_task = asyncio.create_task(receiver())
    seq = 0
    try:
        while not recv_task.done():
            await asyncio.sleep(period)
            pkts, events = sub.drain(core.settings.ws_max_packets_per_batch * 10)
            core.ws_dropped = sub.dropped
            pred = state["pred"]
            shown = [p for p in pkts if pred(p)][-core.settings.ws_max_packets_per_batch :]
            seq += 1
            await ws.send_json(
                {
                    "type": "batch",
                    "seq": seq,
                    "packets": shown,
                    "received": len(pkts),
                    "events": [{"topic": t, "data": d} for t, d in events],
                    "status": core.capture.status(),
                }
            )
    except (WebSocketDisconnect, RuntimeError):
        pass
    finally:
        recv_task.cancel()
        with contextlib.suppress(BaseException):
            await recv_task
        sub.close()

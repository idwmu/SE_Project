"""CaptureModule: live capture (Scapy + libpcap/Npcap) and PCAP replay (PPS-F-001..003, F-030).

One session runs at a time. A supervisor thread owns the session lifecycle:
IDLE -> STARTING -> ACTIVE -> STOPPING -> IDLE, or -> ERROR on failure.
"""

from __future__ import annotations

import sys
import threading
import time
from collections.abc import Callable
from datetime import datetime
from pathlib import Path
from typing import Any

from scapy.packet import Packet
from scapy.utils import PcapReader, PcapWriter

from .bpf import BpfError, validate_bpf
from .bus import EventBus
from .decode import decode
from .detectors import AlertEngine
from .interfaces import list_interfaces
from .stats import LiveStats
from .storage import Storage


class CaptureError(Exception):
    def __init__(self, status: int, code: str, message: str):
        super().__init__(message)
        self.status, self.code, self.message = status, code, message


class CaptureManager:
    def __init__(
        self,
        storage: Storage,
        bus: EventBus,
        replay_dir: Path,
        config_provider: Callable[[], dict[str, Any]],
    ):
        self.storage = storage
        self.bus = bus
        self.replay_dir = Path(replay_dir)
        self.config = config_provider
        self.stats = LiveStats()
        self.state = "IDLE"
        self.error: str | None = None
        self.session: dict[str, Any] | None = None
        self.limits: dict[str, Any] = {}
        self._lock = threading.RLock()
        self._stop = threading.Event()
        self._supervisor: threading.Thread | None = None
        self._writer: PcapWriter | None = None
        self._engine = AlertEngine()
        self._seq = 0
        self._started_mono = 0.0
        self._stop_reason = ""

    # ------------------------------------------------------------------ public API
    def list_replay_files(self) -> list[dict[str, Any]]:
        files = sorted(
            list(self.replay_dir.glob("*.pcap")) + list(self.replay_dir.glob("*.pcapng"))
        )
        return [{"name": p.name, "size": p.stat().st_size} for p in files]

    def status(self) -> dict[str, Any]:
        with self._lock:
            elapsed = time.monotonic() - self._started_mono if self.state == "ACTIVE" else 0
            return {
                "state": self.state,
                "error": self.error,
                "session": self.session,
                "elapsed_s": round(elapsed, 1),
                "limits": self.limits,
                "stats": self.stats.snapshot(),
            }

    def start(
        self,
        *,
        source_type: str,
        source: str,
        bpf: str = "",
        duration_s: int | None = None,
        max_packets: int | None = None,
        replay_speed: float = 1.0,
        user: str = "system",
        authorised: bool = False,
    ) -> dict[str, Any]:
        with self._lock:
            if self.state in ("STARTING", "ACTIVE", "STOPPING"):
                raise CaptureError(409, "CAPTURE_ACTIVE", "A capture session is already running.")
            cfg = self.config()
            duration = int(duration_s if duration_s is not None else cfg["max_duration_s"]) or 0
            limit = int(max_packets if max_packets is not None else cfg["max_packets"]) or 0
            bpf = (bpf or "").strip()

            if source_type == "live":
                if not authorised:
                    raise CaptureError(
                        412,
                        "AUTHORISATION_REQUIRED",
                        "Confirm you are authorised to capture on this network.",
                    )
                names = {i.name for i in list_interfaces()}
                if names and source not in names:
                    raise CaptureError(400, "BAD_INTERFACE", f"Unknown interface {source!r}.")
                try:
                    validate_bpf(bpf, iface=source or None)
                except BpfError as exc:
                    raise CaptureError(
                        400, "BPF_INVALID", f"Invalid capture filter: {exc}"
                    ) from exc
                src_label = f"live:{source}"
            elif source_type == "replay":
                path = (self.replay_dir / source).resolve()
                if path.parent != self.replay_dir.resolve() or not path.is_file():
                    raise CaptureError(404, "NOT_FOUND", f"Replay file {source!r} not found.")
                if bpf:
                    raise CaptureError(
                        400,
                        "BPF_LIVE_ONLY",
                        "Capture (BPF) filters apply to live capture; "
                        "use a display filter for replay.",
                    )
                src_label = f"replay:{source}"
            else:
                raise CaptureError(400, "BAD_SOURCE", "source_type must be 'live' or 'replay'.")

            session_id = self._new_session_id()
            self.session = self.storage.create_session(session_id, src_label, bpf, user)
            self._writer = PcapWriter(
                str(self.storage.pcap_path(session_id)), append=False, sync=False
            )
            self._engine = AlertEngine()
            self._engine.configure(cfg)
            self.stats.reset()
            self._seq = 0
            self._stop.clear()
            self._stop_reason = ""
            self.error = None
            self.limits = {"duration_s": duration, "max_packets": limit}
            self._set_state("STARTING")
            self._supervisor = threading.Thread(
                target=self._run,
                name=f"capture-{session_id}",
                daemon=True,
                args=(source_type, source, bpf, duration, limit, replay_speed),
            )
            self._supervisor.start()

        # wait until the backend is really capturing (or failed) so the API answers truthfully
        deadline = time.monotonic() + 2.0
        while time.monotonic() < deadline and self.state == "STARTING":
            time.sleep(0.02)
        st = self.status()
        if st["state"] == "ERROR":
            raise CaptureError(503, "CAPTURE_FAILED", st["error"] or "Capture failed to start.")
        return st

    def stop(self, user: str = "system", reason: str = "user") -> dict[str, Any]:
        with self._lock:
            if self.state not in ("STARTING", "ACTIVE"):
                raise CaptureError(409, "NOT_ACTIVE", "No capture session is running.")
            self._stop_reason = reason
            self._stop.set()
            sup = self._supervisor
        if sup:
            sup.join(timeout=10)
        return self.status()

    def wait(self, timeout: float | None = None) -> None:
        """Block until the current session ends (used by tests and the benchmark)."""
        if self._supervisor:
            self._supervisor.join(timeout)

    # ------------------------------------------------------------------ internals
    def _new_session_id(self) -> str:
        base = "s_" + datetime.now().strftime("%Y%m%d_%H%M%S")
        sid, n = base, 1
        while self.storage.get_session(sid):
            n += 1
            sid = f"{base}_{n}"
        return sid

    def _set_state(self, state: str) -> None:
        self.state = state
        self.bus.publish("state", {"state": state, "session": self.session, "error": self.error})

    def _limit_hit(self) -> bool:
        lim = self.limits.get("max_packets") or 0
        return bool(lim and self._seq >= lim)

    def _on_packet(self, pkt: Packet) -> None:
        if self._limit_hit():
            return
        self._seq += 1
        assert self._writer is not None
        self._writer.write(pkt)
        d = decode(pkt, self._seq)
        self.stats.add(d.src_ip or d.src_mac, d.protocol, d.length)
        sid = self.session["id"] if self.session else None
        for alert in self._engine.process(d):
            a = alert.to_dict()
            a["id"] = self.storage.save_alert(sid, a)
            a["session_id"] = sid
            self.storage.audit(
                "system", "ALERT_RAISED", {"alert_id": a["id"], "type": a["type"], "session": sid}
            )
            self.bus.publish("alert", a)
        out = d.to_dict()
        out["published_at"] = time.time()
        self.bus.publish("packet", out)

    def _run(
        self, source_type: str, source: str, bpf: str, duration: int, limit: int, speed: float
    ) -> None:
        sniffer = None
        replay_thread = None
        err: str | None = None
        try:
            self._started_mono = time.monotonic()
            if source_type == "live":
                from scapy.sendrecv import AsyncSniffer

                sniffer = AsyncSniffer(
                    iface=source or None,
                    filter=bpf or None,
                    prn=self._on_packet,
                    store=False,
                    promisc=True,
                    stop_filter=lambda _p: self._limit_hit(),
                )
                sniffer.start()
                time.sleep(0.3)  # give libpcap time to open (or fail)
                if not sniffer.running:
                    exc = getattr(sniffer, "exception", None)
                    raise RuntimeError(_friendly_capture_error(exc))
            else:
                replay_thread = threading.Thread(
                    target=self._replay, args=(self.replay_dir / source, speed), daemon=True
                )
                replay_thread.start()
            self._started_mono = time.monotonic()
            self._set_state("ACTIVE")

            while not self._stop.is_set():
                if duration and time.monotonic() - self._started_mono >= duration:
                    self._stop_reason = "duration limit"
                    break
                if self._limit_hit():
                    self._stop_reason = "packet limit"
                    break
                if sniffer is not None and not sniffer.running:
                    exc = getattr(sniffer, "exception", None)
                    if exc:
                        raise RuntimeError(_friendly_capture_error(exc))
                    break
                if replay_thread is not None and not replay_thread.is_alive():
                    self._stop_reason = self._stop_reason or "end of file"
                    break
                time.sleep(0.05)
        except Exception as exc:
            err = str(exc) or type(exc).__name__
        finally:
            self.state = "STOPPING"
            self._stop.set()
            if sniffer is not None and sniffer.running:
                try:
                    sniffer.stop()
                except Exception:
                    pass
            if replay_thread is not None:
                replay_thread.join(timeout=5)
            self._finish(err)

    def _replay(self, path: Path, speed: float) -> None:
        """Feed a PCAP through the pipeline, preserving inter-packet gaps divided by `speed`."""
        first_ts = None
        t0 = time.monotonic()
        with PcapReader(str(path)) as reader:
            for pkt in reader:
                if self._stop.is_set() or self._limit_hit():
                    break
                ts = float(pkt.time)
                if first_ts is None:
                    first_ts = ts
                if speed and speed > 0:
                    due = t0 + (ts - first_ts) / speed
                    while not self._stop.is_set():
                        delay = due - time.monotonic()
                        if delay <= 0:
                            break
                        time.sleep(min(delay, 0.05))
                pkt.time = time.time()  # replayed packets are stamped as captured now
                self._on_packet(pkt)

    def _finish(self, err: str | None) -> None:
        with self._lock:
            if self._writer is not None:
                try:
                    self._writer.close()
                except Exception:
                    pass
                self._writer = None
            snap = self.stats.snapshot()
            sid = self.session["id"] if self.session else None
            if sid:
                self.storage.finish_session(
                    sid, snap["packets"], snap["bytes"], "ERROR" if err else "DONE", err
                )
                self.session = self.storage.get_session(sid)
                if self.session is not None:
                    self.session["stop_reason"] = self._stop_reason or ("error" if err else "user")
                self.storage.audit(
                    "system",
                    "CAPTURE_END",
                    {
                        "session": sid,
                        "packets": snap["packets"],
                        "reason": self._stop_reason or ("error" if err else "user"),
                        "error": err,
                    },
                )
            cfg = self.config()
            removed = self.storage.rotate(
                int(cfg["max_storage_mb"]) * 1024 * 1024, keep={sid} if sid else None
            )
            if removed:
                self.bus.publish(
                    "warning",
                    {
                        "code": "ROTATED",
                        "message": f"Rotated {len(removed)} old session(s) "
                        "to stay within the storage quota.",
                        "sessions": removed,
                    },
                )
            st = self.storage.storage_status(cfg)
            if st["warning"]:
                self.bus.publish(
                    "warning", {"code": "LOW_STORAGE", "message": "Storage is running low.", **st}
                )
            self.error = err
            self._set_state("ERROR" if err else "IDLE")


def _friendly_capture_error(exc: BaseException | None) -> str:
    msg = str(exc) if exc else "Capture backend stopped unexpectedly."
    low = msg.lower()
    if "permission" in low or "operation not permitted" in low:
        hint = (
            "Run with administrator/root rights"
            if sys.platform != "win32"
            else "Install Npcap without 'restrict to administrators', or run as administrator"
        )
        return f"{msg}. {hint}."
    if "libpcap" in low or "winpcap" in low or "npcap" in low:
        return f"{msg}. Install Npcap (Windows) or libpcap (Linux/macOS)."
    return msg

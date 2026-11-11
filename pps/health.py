"""Device health view (PPS-F-062)."""

from __future__ import annotations

import platform
import time
from typing import Any

import psutil

_PROCESS_START = time.time()


def health_snapshot(
    storage_status: dict[str, Any], capture_state: str, ws_clients: int, ws_dropped: int
) -> dict[str, Any]:
    battery = None
    try:
        b = psutil.sensors_battery()
        if b is not None:
            battery = {
                "percent": round(b.percent, 1),
                "plugged_in": bool(b.power_plugged),
                "secs_left": None
                if b.secsleft in (psutil.POWER_TIME_UNLIMITED, psutil.POWER_TIME_UNKNOWN)
                else int(b.secsleft),
            }
    except Exception:
        battery = None
    now = time.time()
    return {
        "battery": battery,  # None when the host has no battery (desktop / VM)
        "storage": storage_status,
        "uptime_s": int(now - _PROCESS_START),
        "system_uptime_s": int(now - psutil.boot_time()),
        "cpu_percent": psutil.cpu_percent(interval=None),
        "memory_percent": psutil.virtual_memory().percent,
        "capture_state": capture_state,
        "ws_clients": ws_clients,
        "ws_dropped_packets": ws_dropped,
        "host": platform.node(),
        "platform": f"{platform.system()} {platform.release()}",
    }

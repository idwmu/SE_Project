"""Runtime configuration for the Pocket Packet Sniffer.

Settings come from ``PPS_*`` environment variables layered over safe
defaults (SRS 4.7: interface selection, capture limits, alert thresholds).
Values are validated eagerly so a bad configuration fails at start-up
rather than in the middle of a capture.
"""

from __future__ import annotations

import os
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

ENV_PREFIX = "PPS_"

_TRUE = frozenset({"1", "true", "yes", "on"})
_FALSE = frozenset({"0", "false", "no", "off"})


class SettingsError(ValueError):
    """Raised when a configuration value is missing, malformed or out of range."""


def _parse_bool(name: str, raw: str) -> bool:
    value = raw.strip().lower()
    if value in _TRUE:
        return True
    if value in _FALSE:
        return False
    raise SettingsError(f"{name} must be a boolean (true/false), got {raw!r}")


def _parse_int(name: str, raw: str) -> int:
    try:
        return int(raw.strip())
    except ValueError:
        raise SettingsError(f"{name} must be an integer, got {raw!r}") from None


@dataclass(frozen=True)
class Settings:
    """Validated PPS configuration.

    ``capture_duration_s`` and ``capture_packet_limit`` use ``None`` for
    "no limit".
    """

    interface: str | None = None
    capture_duration_s: int | None = None
    capture_packet_limit: int | None = None
    data_dir: Path = Path("data")
    api_host: str = "127.0.0.1"
    api_port: int = 8443
    tls_enabled: bool = True
    port_scan_threshold: int = 20
    port_scan_window_s: int = 10
    storage_warn_percent: int = 80
    # Service internals; fixed defaults, not read from the environment.
    token_ttl_s: int = 3600
    pairing_lockout_attempts: int = 5
    pairing_lockout_s: int = 300
    ws_batch_ms: int = 250
    ws_max_packets_per_batch: int = 200

    def __post_init__(self) -> None:
        if self.capture_duration_s is not None and self.capture_duration_s <= 0:
            raise SettingsError("capture_duration_s must be positive")
        if self.capture_packet_limit is not None and self.capture_packet_limit <= 0:
            raise SettingsError("capture_packet_limit must be positive")
        if not 1 <= self.api_port <= 65535:
            raise SettingsError("api_port must be between 1 and 65535")
        if self.port_scan_threshold < 2:
            raise SettingsError("port_scan_threshold must be at least 2")
        if self.port_scan_window_s <= 0:
            raise SettingsError("port_scan_window_s must be positive")
        if not 1 <= self.storage_warn_percent <= 99:
            raise SettingsError("storage_warn_percent must be between 1 and 99")

    @property
    def captures_dir(self) -> Path:
        return self.data_dir / "captures"

    @property
    def replay_dir(self) -> Path:
        return self.data_dir / "replay"

    @property
    def db_path(self) -> Path:
        return self.data_dir / "pps.db"

    def ensure_dirs(self) -> None:
        for d in (self.data_dir, self.captures_dir, self.replay_dir):
            d.mkdir(parents=True, exist_ok=True)

    @classmethod
    def from_env(cls, environ: Mapping[str, str] | None = None) -> Settings:
        """Build settings from ``PPS_*`` variables (defaults for any unset)."""
        env = os.environ if environ is None else environ

        def get(key: str) -> str | None:
            raw = env.get(ENV_PREFIX + key.upper())
            return raw if raw is not None and raw.strip() != "" else None

        values: dict[str, object] = {}
        for key in ("interface", "api_host"):
            raw = get(key)
            if raw is not None:
                values[key] = raw.strip()
        for key in (
            "capture_duration_s",
            "capture_packet_limit",
            "api_port",
            "port_scan_threshold",
            "port_scan_window_s",
            "storage_warn_percent",
        ):
            raw = get(key)
            if raw is not None:
                values[key] = _parse_int(ENV_PREFIX + key.upper(), raw)
        raw = get("tls_enabled")
        if raw is not None:
            values["tls_enabled"] = _parse_bool(ENV_PREFIX + "TLS_ENABLED", raw)
        raw = get("data_dir")
        if raw is not None:
            values["data_dir"] = Path(raw.strip())
        return cls(**values)  # type: ignore[arg-type]


def runtime_defaults(settings: Settings) -> dict:
    """Defaults for the settings an admin can change at runtime (PPS-F-060).

    They start from the validated environment settings; changes made in the
    Settings page are stored in the database and override these.
    """
    return {
        "default_interface": settings.interface or "",
        "max_duration_s": settings.capture_duration_s or 0,  # 0 = no limit
        "max_packets": settings.capture_packet_limit or 0,  # 0 = no limit
        "portscan_threshold": settings.port_scan_threshold,
        "portscan_window_s": settings.port_scan_window_s,
        "arp_whitelist": [],  # entries "ip=mac" that may legitimately change
        "max_storage_mb": 500,
        # warn when less than this % of the quota or disk is left
        "low_space_warn_pct": 100 - settings.storage_warn_percent,
    }


DEFAULT_CONFIG = runtime_defaults(Settings())

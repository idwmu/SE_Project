"""Wires the modules together (one instance per running app)."""

from __future__ import annotations

from .auth import AuthService
from .bus import EventBus
from .capture import CaptureManager
from .settings import Settings, runtime_defaults
from .storage import Storage


class Core:
    def __init__(self, settings: Settings, pin: str | None = None):
        settings.ensure_dirs()
        self.settings = settings
        self.storage = Storage(settings.db_path, settings.captures_dir, runtime_defaults(settings))
        self.bus = EventBus()
        self.auth = AuthService(
            self.storage,
            settings.data_dir / "secret.key",
            settings.token_ttl_s,
            settings.pairing_lockout_attempts,
            settings.pairing_lockout_s,
            pin=pin,
        )
        self.capture = CaptureManager(
            self.storage, self.bus, settings.replay_dir, self.storage.get_config
        )
        self.ws_dropped = 0

    def close(self) -> None:
        if self.capture.state in ("STARTING", "ACTIVE"):
            try:
                self.capture.stop(reason="shutdown")
            except Exception:
                pass
        self.storage.close()

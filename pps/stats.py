"""Live traffic statistics: counts, rates, top talkers and protocols."""

from __future__ import annotations

import threading
import time
from collections import Counter, deque


class LiveStats:
    def __init__(self, window_s: float = 1.0):
        self.window_s = window_s
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        with getattr(self, "_lock", threading.Lock()):
            self.packets = 0
            self.bytes = 0
            self.talkers: Counter[str] = Counter()
            self.protocols: Counter[str] = Counter()
            self._recent: deque[tuple[float, int]] = deque()
            self.started = time.monotonic()

    def add(self, src: str | None, protocol: str, length: int) -> None:
        now = time.monotonic()
        with self._lock:
            self.packets += 1
            self.bytes += length
            if src:
                self.talkers[src] += 1
            self.protocols[protocol] += 1
            self._recent.append((now, length))
            self._trim(now)

    def _trim(self, now: float) -> None:
        while self._recent and now - self._recent[0][0] > self.window_s:
            self._recent.popleft()

    def snapshot(self) -> dict:
        now = time.monotonic()
        with self._lock:
            self._trim(now)
            pps = len(self._recent) / self.window_s
            bps = sum(b for _, b in self._recent) * 8 / self.window_s
            return {
                "packets": self.packets,
                "bytes": self.bytes,
                "pps": round(pps, 1),
                "bandwidth_bps": round(bps),
                "top_talkers": self.talkers.most_common(5),
                "top_protocols": self.protocols.most_common(6),
            }

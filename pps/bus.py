"""EventBus: in-process publish/subscribe between the capture thread and async consumers."""

from __future__ import annotations

import asyncio
import threading
from collections import deque
from typing import Any

# Topics whose events must never be dropped, even when a subscriber is slow.
LOSSLESS_TOPICS = {"alert", "state", "warning"}


class Subscription:
    def __init__(self, bus: EventBus, topics: set[str], maxlen: int):
        self.bus = bus
        self.topics = topics
        self.packets: deque[Any] = deque(maxlen=maxlen)  # lossy: oldest dropped first
        self.events: deque[tuple[str, Any]] = deque()  # lossless
        self.dropped = 0
        self._lock = threading.Lock()

    def push(self, topic: str, item: Any) -> None:
        with self._lock:
            if topic in LOSSLESS_TOPICS:
                self.events.append((topic, item))
            else:
                if len(self.packets) == self.packets.maxlen:
                    self.dropped += 1
                self.packets.append(item)

    def drain(self, max_packets: int) -> tuple[list[Any], list[tuple[str, Any]]]:
        with self._lock:
            n = min(max_packets, len(self.packets))
            # newest packets are most relevant for a live view
            pkts = list(self.packets)[-n:] if n else []
            self.packets.clear()
            evs = list(self.events)
            self.events.clear()
        return pkts, evs

    def close(self) -> None:
        self.bus.unsubscribe(self)


class EventBus:
    """Thread-safe fan-out. Producers call publish() from any thread."""

    def __init__(self) -> None:
        self._subs: list[Subscription] = []
        self._lock = threading.Lock()
        self.wakeup: asyncio.Event | None = None

    def subscribe(self, topics: set[str] | None = None, maxlen: int = 2000) -> Subscription:
        sub = Subscription(self, topics or {"packet", "alert", "state", "warning"}, maxlen)
        with self._lock:
            self._subs.append(sub)
        return sub

    def unsubscribe(self, sub: Subscription) -> None:
        with self._lock:
            if sub in self._subs:
                self._subs.remove(sub)

    def publish(self, topic: str, item: Any) -> None:
        with self._lock:
            subs = list(self._subs)
        for s in subs:
            if topic in s.topics:
                s.push(topic, item)

    @property
    def subscriber_count(self) -> int:
        with self._lock:
            return len(self._subs)

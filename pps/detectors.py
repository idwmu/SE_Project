"""AlertModule detectors (PPS-F-040, PPS-F-041).

Detectors are plug-ins: each receives every DecodedPacket and returns zero or more Alert objects.
They use packet timestamps (not wall-clock time) so recorded PCAPs replay deterministically.
"""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any, Protocol

from .decode import DecodedPacket


@dataclass
class Alert:
    type: str
    severity: str
    ts: float
    message: str
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def ts_iso(self) -> str:
        return datetime.fromtimestamp(self.ts, tz=timezone.utc).isoformat(timespec="milliseconds")

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["ts_iso"] = self.ts_iso
        return d


class Detector(Protocol):
    name: str

    def process(self, pkt: DecodedPacket) -> list[Alert]: ...

    def configure(self, config: dict[str, Any]) -> None: ...


def _arp_fields(pkt: DecodedPacket) -> dict[str, Any] | None:
    for layer in pkt.layers:
        if layer["proto"] == "ARP":
            return layer["fields"]
    return None


class ArpSpoofDetector:
    """Flags an IP whose MAC binding changes (classic ARP cache poisoning signature)."""

    name = "arp_spoof"

    def __init__(self, whitelist: list[str] | None = None, realert_s: float = 60.0):
        self.bindings: dict[str, str] = {}
        self.whitelist: set[tuple[str, str]] = set()
        self.realert_s = realert_s
        self._last_alert: dict[tuple[str, str], float] = {}
        self.configure({"arp_whitelist": whitelist or []})

    def configure(self, config: dict[str, Any]) -> None:
        wl = set()
        for entry in config.get("arp_whitelist", []) or []:
            if "=" in entry:
                ip, mac = entry.split("=", 1)
                wl.add((ip.strip(), mac.strip().lower()))
        self.whitelist = wl

    def process(self, pkt: DecodedPacket) -> list[Alert]:
        f = _arp_fields(pkt)
        if not f or f.get("op") != "is-at":
            return []

        ip, mac = str(f["psrc"]), str(f["hwsrc"]).lower()

        if ip in ("0.0.0.0",) or mac in (
            "00:00:00:00:00:00",
            "ff:ff:ff:ff:ff:ff",
        ):
            return []

        known = self.bindings.get(ip)

        if known is None:
            self.bindings[ip] = mac
            return []

        if known == mac or (ip, mac) in self.whitelist:
            return []

        key = (ip, mac)
        last = self._last_alert.get(key)

        if last is not None and pkt.ts - last < self.realert_s:
            return []

        self._last_alert[key] = pkt.ts

        return [
            Alert(
                type="ARP_SPOOF",
                severity="HIGH",
                ts=pkt.ts,
                message=f"ARP spoofing suspected: {ip} moved from {known} to {mac}",
                details={
                    "ip": ip,
                    "old_mac": known,
                    "new_mac": mac,
                },
            )
        ]


class PortScanDetector:
    """Flags a source that probes many distinct destination ports within a sliding window."""

    name = "port_scan"

    def __init__(
        self,
        threshold: int = 15,
        window_s: float = 10.0,
        realert_s: float = 60.0,
    ):
        self.threshold = threshold
        self.window_s = window_s
        self.realert_s = realert_s
        self._probes: dict[tuple[str, str], deque[tuple[float, int]]] = defaultdict(deque)
        self._last_alert: dict[tuple[str, str], float] = {}

    def configure(self, config: dict[str, Any]) -> None:
        self.threshold = int(config.get("portscan_threshold", self.threshold))
        self.window_s = float(config.get("portscan_window_s", self.window_s))

    @staticmethod
    def _is_probe(pkt: DecodedPacket) -> bool:
        if pkt.dst_port is None or pkt.src_ip is None:
            return False

        if pkt.tcp_flags is not None:
            flags = set(pkt.tcp_flags.split(",")) if pkt.tcp_flags else set()

            # Connection attempt or NULL / FIN / XMAS-style probes.
            return (
                ("SYN" in flags and "ACK" not in flags)
                or not flags
                or flags <= {"FIN", "PSH", "URG"}
            )

        return "udp" in pkt.protos and pkt.app_proto is None

    def process(self, pkt: DecodedPacket) -> list[Alert]:
        if not self._is_probe(pkt):
            return []

        key = (str(pkt.src_ip), str(pkt.dst_ip))
        q = self._probes[key]

        q.append((pkt.ts, int(pkt.dst_port)))  # type: ignore[arg-type]

        while q and pkt.ts - q[0][0] > self.window_s:
            q.popleft()

        ports = {p for _, p in q}

        if len(ports) < self.threshold:
            return []

        last = self._last_alert.get(key)

        if last is not None and pkt.ts - last < self.realert_s:
            return []

        self._last_alert[key] = pkt.ts
        sample = sorted(ports)[:10]

        return [
            Alert(
                type="PORT_SCAN",
                severity="MEDIUM",
                ts=pkt.ts,
                message=(
                    f"Port scan suspected: {key[0]} probed "
                    f"{len(ports)} ports on {key[1]} "
                    f"in {self.window_s:g}s"
                ),
                details={
                    "src_ip": key[0],
                    "dst_ip": key[1],
                    "port_count": len(ports),
                    "sample_ports": sample,
                },
            )
        ]


class AlertEngine:
    def __init__(self, detectors: list[Any] | None = None):
        self.detectors = (
            detectors if detectors is not None else [ArpSpoofDetector(), PortScanDetector()]
        )

    def configure(self, config: dict[str, Any]) -> None:
        for detector in self.detectors:
            detector.configure(config)

    def process(self, pkt: DecodedPacket) -> list[Alert]:
        out: list[Alert] = []

        for detector in self.detectors:
            out.extend(detector.process(pkt))

        return out

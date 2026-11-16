"""Performance benchmark for PPS-NF-001 (live-view latency) and PPS-NF-003 (packet loss).

Replays synthetic traffic at fixed packet rates through the real capture pipeline
(decode, detectors, PCAP writer, event bus) and consumes it the same way the WebSocket
does (drain every 250 ms). Latency = time a packet is delivered to the live-view consumer
minus the time it entered the pipeline. Browser rendering is not included.

    python tools/benchmark.py [--rates 100 500 1000] [--seconds 10]
"""

from __future__ import annotations

import argparse
import logging
import statistics
import sys
import tempfile
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.layers.inet import IP, UDP  # noqa: E402
from scapy.layers.l2 import Ether  # noqa: E402
from scapy.packet import Raw  # noqa: E402
from scapy.utils import wrpcap  # noqa: E402

from pps.core import Core  # noqa: E402
from pps.settings import Settings  # noqa: E402


def make_stream(path: Path, rate: int, seconds: float) -> int:
    n = int(rate * seconds)
    pkts = []

    for i in range(n):
        packet = (
            Ether()
            / IP(src=f"10.1.{i % 200}.{i % 250 + 1}", dst="10.2.0.1")
            / UDP(sport=40000 + i % 1000, dport=9999)
            / Raw(i.to_bytes(4, "big") + bytes(60))
        )
        packet.time = 1_700_000_000 + i / rate
        pkts.append(packet)

    wrpcap(str(path), pkts)
    return n


def run(rate: int, seconds: float) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        settings = Settings(data_dir=Path(tmp))
        core = Core(settings, pin="000000")
        n = make_stream(settings.replay_dir / "bench.pcap", rate, seconds)
        sub = core.bus.subscribe(maxlen=100_000)

        lat: list[float] = []
        delivered = 0
        done = threading.Event()

        def consumer() -> None:
            nonlocal delivered

            while not done.is_set() or sub.packets:
                time.sleep(0.25)
                pkts, _ = sub.drain(10**9)
                now = time.time()
                delivered += len(pkts)
                lat.extend(now - packet["ts"] for packet in pkts)

        thread = threading.Thread(target=consumer, daemon=True)
        thread.start()

        core.capture.start(
            source_type="replay",
            source="bench.pcap",
            replay_speed=1.0,
            duration_s=0,
            max_packets=0,
        )
        core.capture.wait(seconds + 30)

        captured = core.capture.status()["session"]["packets"]

        time.sleep(0.6)
        done.set()
        thread.join(5)
        core.close()

    lat.sort()
    p90 = lat[int(0.9 * (len(lat) - 1))] if lat else float("nan")

    return {
        "rate": rate,
        "sent": n,
        "captured": captured,
        "delivered": delivered,
        "loss_pct": 100.0 * (n - captured) / n,
        "p50_ms": 1000 * statistics.median(lat) if lat else float("nan"),
        "p90_ms": 1000 * p90,
        "max_ms": 1000 * lat[-1] if lat else float("nan"),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--rates",
        type=int,
        nargs="+",
        default=[100, 500, 1000],
    )
    parser.add_argument("--seconds", type=float, default=10)
    args = parser.parse_args()

    header = (
        f"{'pkt/s':>6} {'sent':>7} {'captured':>9} "
        f"{'loss %':>7} {'p50 ms':>8} {'p90 ms':>8} {'max ms':>8}  "
        "NF-001 / NF-003"
    )
    print(header)

    ok = True

    for rate in args.rates:
        result = run(rate, args.seconds)
        passed = result["p90_ms"] <= 1000 and result["loss_pct"] <= 1.0
        ok &= passed

        row = (
            f"{rate:>6} {result['sent']:>7} {result['captured']:>9} "
            f"{result['loss_pct']:>7.2f} {result['p50_ms']:>8.1f} "
            f"{result['p90_ms']:>8.1f} {result['max_ms']:>8.1f}  "
            f"{'PASS' if passed else 'FAIL'}"
        )
        print(row)

    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())

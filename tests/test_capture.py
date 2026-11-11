"""TC-Cap-02 / TC-Sto-01 at module level: CaptureManager replay, limits, PCAP output."""

import shutil

from scapy.utils import rdpcap

from pps.bus import EventBus
from pps.capture import CaptureError, CaptureManager
from pps.settings import DEFAULT_CONFIG
from pps.storage import Storage


def manager(tmp_path, demo_dir):
    replay = tmp_path / "replay"
    shutil.copytree(demo_dir, replay)
    st = Storage(tmp_path / "db.sqlite", tmp_path / "caps")
    bus = EventBus()
    return CaptureManager(st, bus, replay, lambda: dict(DEFAULT_CONFIG)), st, bus


def test_replay_writes_all_packets(tmp_path, demo_dir):
    cm, st, bus = manager(tmp_path, demo_dir)
    sub = bus.subscribe()
    cm.start(source_type="replay", source="normal_traffic.pcap", replay_speed=0)
    cm.wait(20)
    s = cm.status()
    expected = len(rdpcap(str(demo_dir / "normal_traffic.pcap")))
    assert s["state"] == "IDLE" and s["session"]["packets"] == expected
    assert len(rdpcap(str(st.pcap_path(s["session"]["id"])))) == expected
    pkts, events = sub.drain(10**6)
    assert len(pkts) == expected
    assert [e for t, e in events if t == "state"][-1]["state"] == "IDLE"


def test_packet_limit(tmp_path, demo_dir):
    cm, st, _ = manager(tmp_path, demo_dir)
    cm.start(source_type="replay", source="demo_all.pcap", replay_speed=0, max_packets=25)
    cm.wait(20)
    assert cm.status()["session"]["packets"] == 25


def test_errors(tmp_path, demo_dir):
    cm, _, _ = manager(tmp_path, demo_dir)
    for kwargs, code in [
        ({"source_type": "replay", "source": "missing.pcap"}, "NOT_FOUND"),
        ({"source_type": "replay", "source": "../../etc/passwd"}, "NOT_FOUND"),
        ({"source_type": "bogus", "source": "x"}, "BAD_SOURCE"),
        ({"source_type": "live", "source": "lo"}, "AUTHORISATION_REQUIRED"),
    ]:
        try:
            cm.start(**kwargs)
        except CaptureError as e:
            assert e.code == code
        else:
            raise AssertionError(kwargs)


def test_alerts_published_and_stored(tmp_path, demo_dir):
    cm, st, bus = manager(tmp_path, demo_dir)
    sub = bus.subscribe()
    cm.start(source_type="replay", source="arp_spoof.pcap", replay_speed=0)
    cm.wait(20)
    _, events = sub.drain(0)
    assert [d["type"] for t, d in events if t == "alert"] == ["ARP_SPOOF"]
    assert st.list_alerts()[0]["details"]["new_mac"] == "02:50:00:00:00:66"


def test_live_start_rejects_unknown_interface(tmp_path, demo_dir, monkeypatch):
    # list_interfaces() returns InterfaceInfo objects (PR 08), not dicts.
    from pps import capture
    from pps.interfaces import InterfaceInfo

    eth0 = InterfaceInfo(
        name="eth0",
        description="Ethernet",
        mac=None,
        ips=(),
        is_up=True,
        is_loopback=False,
        is_wireless=False,
        monitor_capable=None,
        in_monitor_mode=False,
    )
    monkeypatch.setattr(capture, "list_interfaces", lambda: [eth0])
    cm, _, _ = manager(tmp_path, demo_dir)
    try:
        cm.start(source_type="live", source="nope0", authorised=True)
    except CaptureError as e:
        assert e.code == "BAD_INTERFACE"
    else:
        raise AssertionError("unknown interface accepted")


def test_core_wires_modules(tmp_path):
    from pps.core import Core
    from pps.settings import Settings

    core = Core(Settings(data_dir=tmp_path), pin="123456")
    try:
        assert core.auth.pin == "123456"
        assert core.capture.state == "IDLE"
    finally:
        core.close()

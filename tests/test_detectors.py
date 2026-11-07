"""Tests for ARP spoofing and port scan detection, including false positives."""

from scapy.utils import PcapReader

from pps.decode import decode
from pps.detectors import AlertEngine, ArpSpoofDetector, PortScanDetector


def run(path, engine=None):
    engine = engine or AlertEngine()
    alerts = []

    with PcapReader(str(path)) as reader:
        for i, packet in enumerate(reader, 1):
            alerts += engine.process(decode(packet, i))

    return alerts


def test_arp_spoof_detected(demo_dir):
    alerts = run(demo_dir / "arp_spoof.pcap")
    arp = [alert for alert in alerts if alert.type == "ARP_SPOOF"]

    assert len(arp) == 1
    assert arp[0].details == {
        "ip": "192.168.50.1",
        "old_mac": "02:50:00:00:00:01",
        "new_mac": "02:50:00:00:00:66",
    }
    assert arp[0].severity == "HIGH"


def test_port_scan_detected(demo_dir):
    alerts = [alert for alert in run(demo_dir / "port_scan.pcap") if alert.type == "PORT_SCAN"]

    assert len(alerts) == 1
    assert alerts[0].details["src_ip"] == "192.168.50.66"
    assert alerts[0].details["dst_ip"] == "192.168.50.20"


def test_no_false_positives_on_normal_traffic(demo_dir):
    assert run(demo_dir / "normal_traffic.pcap") == []


def test_whitelisted_arp_change_is_ignored(demo_dir):
    engine = AlertEngine(
        [
            ArpSpoofDetector(whitelist=["192.168.50.1=02:50:00:00:00:66"]),
            PortScanDetector(),
        ]
    )

    alerts = run(demo_dir / "arp_spoof.pcap", engine)

    assert [alert for alert in alerts if alert.type == "ARP_SPOOF"] == []


def test_port_scan_threshold_configurable(demo_dir):
    engine = AlertEngine()
    engine.configure(
        {
            "portscan_threshold": 500,
            "portscan_window_s": 10,
        }
    )

    alerts = [
        alert for alert in run(demo_dir / "port_scan.pcap", engine) if alert.type == "PORT_SCAN"
    ]

    assert alerts == []


def test_both_detectors_fire_on_combined_demo(demo_dir):
    types = sorted(alert.type for alert in run(demo_dir / "demo_all.pcap"))

    assert types == ["ARP_SPOOF", "PORT_SCAN"]

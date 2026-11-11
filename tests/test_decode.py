"""TC-Dec-01 / TC-Dec-02: decoding and DNS/HTTP labelling against known packets."""

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import PcapReader

from pps.decode import decode


def built(p):
    if p.haslayer(Ether):
        packet = p[Ether]
        fields = packet.fields
        packet.src = fields.get("src") or "02:00:00:00:00:01"
        packet.dst = fields.get("dst") or "02:00:00:00:00:02"
    return Ether(bytes(p))


def test_ethernet_ipv4_tcp_fields():
    p = built(
        Ether(src="02:00:00:00:00:01", dst="02:00:00:00:00:02")
        / IP(src="10.0.0.1", dst="10.0.0.2", ttl=61)
        / TCP(sport=40000, dport=22, flags="S", seq=100)
    )
    d = decode(p, 1)
    assert d.protocol == "TCP"
    assert (d.src_mac, d.dst_mac) == ("02:00:00:00:00:01", "02:00:00:00:00:02")
    assert (d.src_ip, d.dst_ip, d.src_port, d.dst_port) == ("10.0.0.1", "10.0.0.2", 40000, 22)
    assert d.tcp_flags == "SYN"
    ip = next(layer for layer in d.layers if layer["proto"] == "IPv4")
    assert ip["fields"]["ttl"] == 61
    assert [layer["proto"] for layer in d.layers] == ["Ethernet", "IPv4", "TCP"]


def test_ipv6_udp():
    d = decode(
        built(Ether() / IPv6(src="fe80::1", dst="fe80::2", hlim=5) / UDP(sport=1000, dport=2000))
    )
    assert d.protocol == "UDP" and d.src_ip == "fe80::1" and d.dst_port == 2000
    assert "ipv6" in d.protos and "ip" in d.protos


def test_icmp():
    d = decode(built(Ether() / IP(src="1.1.1.1", dst="2.2.2.2") / ICMP(type=8)))
    assert d.protocol == "ICMP" and d.info == "echo-request"


def test_arp_reply():
    d = decode(
        built(
            Ether(src="02:00:00:00:00:09", dst="02:00:00:00:00:01")
            / ARP(op=2, psrc="192.168.1.1", hwsrc="02:00:00:00:00:09", pdst="192.168.1.5")
        )
    )
    assert d.protocol == "ARP"
    assert d.layers[-1]["fields"]["op"] == "is-at"
    assert d.info == "192.168.1.1 is at 02:00:00:00:00:09"


def test_dns_query_and_response_labelled():
    q = decode(
        built(Ether() / IP() / UDP(sport=5555, dport=53) / DNS(rd=1, qd=DNSQR(qname="pes.edu")))
    )
    r = decode(
        built(
            Ether()
            / IP()
            / UDP(sport=53, dport=5555)
            / DNS(qr=1, qd=DNSQR(qname="pes.edu"), an=DNSRR(rrname="pes.edu", rdata="203.0.113.10"))
        )
    )
    assert q.app_proto == "DNS" and q.info == "DNS query A pes.edu"
    assert r.app_proto == "DNS" and r.info.endswith("-> 203.0.113.10")


def test_http_by_signature_on_any_port():
    req = decode(
        built(
            Ether()
            / IP()
            / TCP(sport=5000, dport=8080, flags="PA")
            / Raw(b"GET /a HTTP/1.1\r\nHost: x.test\r\n\r\n")
        )
    )
    resp = decode(
        built(
            Ether()
            / IP()
            / TCP(sport=80, dport=5000, flags="PA")
            / Raw(b"HTTP/1.1 404 Not Found\r\n\r\n")
        )
    )
    assert req.app_proto == "HTTP" and req.layers[-1]["fields"]["host"] == "x.test"
    assert resp.app_proto == "HTTP" and resp.layers[-1]["fields"]["status"] == "404"


def test_non_http_tcp_payload_not_labelled():
    d = decode(
        built(
            Ether()
            / IP()
            / TCP(sport=443, dport=5000, flags="PA")
            / Raw(b"\x17\x03\x03\x00\x10" + b"x" * 16)
        )
    )
    assert d.app_proto is None and d.protocol == "TCP"


def test_labelled_demo_set_accuracy(demo_dir):
    """TC-Dec-02: >= 95% of DNS/HTTP packets in the demo set are labelled correctly."""
    expected = correct = 0
    with PcapReader(str(demo_dir / "normal_traffic.pcap")) as rd:
        for p in rd:
            truth = None
            if p.haslayer(UDP) and 53 in (p[UDP].sport, p[UDP].dport):
                truth = "DNS"
            elif p.haslayer(TCP) and len(p[TCP].payload) and 80 in (p[TCP].sport, p[TCP].dport):
                truth = "HTTP"
            if truth:
                expected += 1
                correct += decode(p).app_proto == truth
    assert expected > 50
    assert correct / expected >= 0.95

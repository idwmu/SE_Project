"""TC-Filt-02 / TC-Filt-03: display filters and combinations."""

import pytest
from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw

from pps.decode import decode
from pps.displayfilter import FilterError, compile_filter

ETHER = {"src": "02:00:00:00:00:0a", "dst": "02:00:00:00:00:01"}
PKTS = [
    Ether(**ETHER)
    / IP(src="192.168.50.10", dst="93.184.216.34")
    / TCP(sport=50000, dport=80, flags="PA")
    / Raw(b"GET / HTTP/1.1\r\n\r\n"),
    Ether(**ETHER)
    / IP(src="192.168.50.10", dst="192.168.50.1")
    / UDP(sport=5000, dport=53)
    / DNS(qd=DNSQR(qname="a.test")),
    Ether(src="02:00:00:00:00:01", dst="ff:ff:ff:ff:ff:ff")
    / ARP(
        op=1,
        hwsrc="02:00:00:00:00:01",
        hwdst="00:00:00:00:00:00",
        psrc="192.168.50.1",
        pdst="192.168.50.10",
    ),
    Ether(**ETHER) / IP(src="10.0.0.1", dst="10.0.0.2") / ICMP(),
    Ether(**ETHER) / IP(src="10.0.0.1", dst="10.0.0.2") / TCP(sport=1234, dport=443, flags="S"),
]
D = [decode(Ether(bytes(p)), i).to_dict() for i, p in enumerate(PKTS)]


def match(expr):
    f = compile_filter(expr)
    return [i for i, p in enumerate(D) if f(p)]


@pytest.mark.parametrize("expr,expected", [
    ("", [0, 1, 2, 3, 4]),
    ("dns", [1]),
    ("http", [0]),
    ("tcp", [0, 4]),
    ("arp", [2]),
    ("ip.src == 192.168.50.10", [0, 1]),
    ("ip.addr == 10.0.0.2", [3, 4]),
    ("port == 443", [4]),
    ("tcp.port == 80", [0]),
    ("udp.port == 53", [1]),
    ("dst.port > 100", [4]),
    ("ip.addr == 192.168.50.1", [1]),  # ip.* does not match the ARP frame (same as Wireshark)
    ("mac == ff:ff:ff:ff:ff:ff", [2]),
    ("eth.src == 02:00:00:00:00:0A", [0, 1, 3, 4]),  # case-insensitive
    ("proto == icmp", [3]),
    ('info contains "GET"', [0]),
    ("tcp.flags contains SYN", [4]),
])
def test_single_conditions(expr, expected):
    assert match(expr) == expected


@pytest.mark.parametrize("expr,expected", [
    ("dns or http", [0, 1]),
    ("ip.addr == 192.168.50.10 and not dns", [0]),
    ("tcp && !http", [4]),
    ("(dns or arp) and (ip.addr == 192.168.50.1 or mac == 02:00:00:00:00:01)", [1, 2]),
    ("not (tcp or udp)", [2, 3]),
    ("tcp or udp and ip.dst == 192.168.50.1", [0, 1, 4]),  # and binds tighter than or
    ("! ip", [2]),
    ("ip.src == 10.0.0.1 || mac == ff:ff:ff:ff:ff:ff", [2, 3, 4]),
])
def test_combinations(expr, expected):
    assert match(expr) == expected


@pytest.mark.parametrize(
    "bad",
    ["ip.src == nope", "tcp.port 80", "(dns", "dns)", "foo", "ip.src ==", "port",
     "dns and", "== 5", "ip.src = 1.2.3.4"],
)
def test_invalid_filters_raise(bad):
    with pytest.raises(FilterError):
        compile_filter(bad)

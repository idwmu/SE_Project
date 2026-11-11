"""TC-Rob-01: the decoder must not crash or hang on malformed / truncated frames."""

import random
import time

from scapy.layers.dns import DNS, DNSQR
from scapy.layers.inet import IP, TCP, UDP
from scapy.layers.l2 import Ether
from scapy.packet import Raw

from pps.decode import decode
from pps.displayfilter import compile_filter


def test_fuzzed_frames_never_crash():
    random.seed(1)
    ether = {"src": "02:00:00:00:00:0a", "dst": "02:00:00:00:00:01"}
    base = [
        bytes(Ether(**ether) / IP() / TCP(dport=80) / Raw(b"GET / HTTP/1.1\r\n\r\n")),
        bytes(Ether(**ether) / IP() / UDP(dport=53) / DNS(qd=DNSQR(qname="x.test"))),
    ]
    f = compile_filter("dns or http or tcp.port == 80")
    worst = 0.0
    for i in range(3000):
        b = bytearray(random.choice(base))
        for _ in range(random.randint(1, 6)):
            b[random.randrange(len(b))] = random.randrange(256)
        b = bytes(b[: random.randint(1, len(b))])
        t = time.perf_counter()
        try:  # mimic Scapy's socket/PcapReader behaviour: undecodable bytes become Raw
            pkt = Ether(b)
        except Exception:
            pkt = Raw(b)
        d = decode(pkt, i)
        f(d.to_dict())
        worst = max(worst, time.perf_counter() - t)
        assert d.protocol
    assert worst < 0.1  # no packet takes more than 100 ms

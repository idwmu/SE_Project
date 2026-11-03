"""Generate synthetic, lab-safe PCAPs for demos and tests.

All addresses are private lab addresses (192.168.50.0/24) or documentation/public examples.
No real network is touched: packets are built in memory and written to files.

    python tools/make_demo_pcaps.py [output_dir]      (default: pps_data/replay)
"""

from __future__ import annotations

import random
import sys
from pathlib import Path

from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Raw
from scapy.utils import wrpcap

GW_IP, GW_MAC = "192.168.50.1", "02:50:00:00:00:01"
HOST_IP, HOST_MAC = "192.168.50.10", "02:50:00:00:00:10"
PEER_IP, PEER_MAC = "192.168.50.20", "02:50:00:00:00:20"
ATTACKER_IP, ATTACKER_MAC = "192.168.50.66", "02:50:00:00:00:66"
SITES = [
    ("example.com", "93.184.216.34"),
    ("pes.edu", "203.0.113.10"),
    ("wikipedia.org", "198.51.100.7"),
    ("github.com", "198.51.100.42"),
]


def _stamp(pkts: list, t0: float, gaps: list[float]) -> list:
    t = t0
    for p, g in zip(pkts, gaps, strict=True):
        t += g
        p.time = t
    return pkts


def arp_exchange(t: float, ip: str = GW_IP, mac: str = GW_MAC, asker_ip: str = HOST_IP,
                 asker_mac: str = HOST_MAC) -> list:
    req = (
        Ether(src=asker_mac, dst="ff:ff:ff:ff:ff:ff")
        / ARP(op=1, hwsrc=asker_mac, psrc=asker_ip, pdst=ip)
    )
    rep = (
        Ether(src=mac, dst=asker_mac)
        / ARP(op=2, hwsrc=mac, psrc=ip, hwdst=asker_mac, pdst=asker_ip)
    )
    return _stamp([req, rep], t, [0, 0.002])


def dns_lookup(t: float, name: str, addr: str, sport: int) -> list:
    tid = random.randint(1, 65535)
    q = (Ether(src=HOST_MAC, dst=GW_MAC) / IP(src=HOST_IP, dst=GW_IP) / UDP(sport=sport, dport=53)
         / DNS(id=tid, rd=1, qd=DNSQR(qname=name)))
    r = (Ether(src=GW_MAC, dst=HOST_MAC) / IP(src=GW_IP, dst=HOST_IP) / UDP(sport=53, dport=sport)
         / DNS(
             id=tid, qr=1, ra=1, qd=DNSQR(qname=name),
             an=DNSRR(rrname=name, rdata=addr, ttl=300),
         ))
    return _stamp([q, r], t, [0, 0.018])


def http_get(t: float, name: str, addr: str, sport: int, path: str = "/") -> list:
    c = Ether(src=HOST_MAC, dst=GW_MAC) / IP(src=HOST_IP, dst=addr)
    s = Ether(src=GW_MAC, dst=HOST_MAC) / IP(src=addr, dst=HOST_IP)
    seq, ack = random.randint(1000, 10**9), random.randint(1000, 10**9)
    req = f"GET {path} HTTP/1.1\r\nHost: {name}\r\nUser-Agent: pps-demo\r\n\r\n".encode()
    body = b"<html><body>demo</body></html>"
    resp = (b"HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: "
            + str(len(body)).encode() + b"\r\n\r\n" + body)
    pkts = [
        c / TCP(sport=sport, dport=80, flags="S", seq=seq),
        s / TCP(sport=80, dport=sport, flags="SA", seq=ack, ack=seq + 1),
        c / TCP(sport=sport, dport=80, flags="A", seq=seq + 1, ack=ack + 1),
        c / TCP(sport=sport, dport=80, flags="PA", seq=seq + 1, ack=ack + 1) / Raw(req),
        s / TCP(sport=80, dport=sport, flags="PA", seq=ack + 1, ack=seq + 1 + len(req)) / Raw(resp),
        c / TCP(sport=sport, dport=80, flags="FA", seq=seq + 1 + len(req), ack=ack + 1 + len(resp)),
        s / TCP(sport=80, dport=sport, flags="FA", seq=ack + 1 + len(resp), ack=seq + 2 + len(req)),
    ]
    return _stamp(pkts, t, [0, 0.03, 0.001, 0.001, 0.04, 0.01, 0.02])


def https_burst(t: float, addr: str, sport: int, n: int = 6) -> list:
    c = Ether(src=HOST_MAC, dst=GW_MAC) / IP(src=HOST_IP, dst=addr)
    s = Ether(src=GW_MAC, dst=HOST_MAC) / IP(src=addr, dst=HOST_IP)
    seq, ack = random.randint(1000, 10**9), random.randint(1000, 10**9)
    pkts = [c / TCP(sport=sport, dport=443, flags="S", seq=seq),
            s / TCP(sport=443, dport=sport, flags="SA", seq=ack, ack=seq + 1),
            c / TCP(sport=sport, dport=443, flags="A", seq=seq + 1, ack=ack + 1)]
    for i in range(n):
        pkt = (
            (s if i % 2 else c)
            / TCP(sport=443 if i % 2 else sport, dport=sport if i % 2 else 443, flags="PA")
            / Raw(b"\x17\x03\x03" + bytes(random.randint(40, 600)))
        )
        pkts.append(pkt)
    return _stamp(pkts, t, [0, 0.03, 0.001] + [0.01] * n)


def ping(t: float, dst: str = GW_IP, count: int = 3) -> list:
    out = []
    for i in range(count):
        req = Ether(src=HOST_MAC, dst=GW_MAC) / IP(src=HOST_IP, dst=dst) / ICMP(type=8, id=7, seq=i)
        rep = Ether(src=GW_MAC, dst=HOST_MAC) / IP(src=dst, dst=HOST_IP) / ICMP(type=0, id=7, seq=i)
        out += _stamp([req, rep], t + i, [0, 0.004])
    return out


def normal_traffic(t0: float, seconds: float) -> list:
    pkts = arp_exchange(t0)
    t, sport = t0 + 0.1, 49152
    while t < t0 + seconds:
        name, addr = random.choice(SITES)
        kind = random.random()
        if kind < 0.35:
            pkts += dns_lookup(t, name, addr, sport)
        elif kind < 0.65:
            dns = dns_lookup(t, name, addr, sport)
            path = random.choice(["/", "/index.html", "/news"])
            pkts += dns + http_get(t + 0.05, name, addr, sport + 1, path)
        elif kind < 0.9:
            pkts += https_burst(t, addr, sport)
        else:
            pkts += ping(t, count=2)
        sport += 2
        t += random.uniform(0.3, 1.2)
    return pkts


def arp_spoof(t: float, count: int = 6) -> list:
    """Attacker claims the gateway IP (ARP cache poisoning)."""
    out = []
    for i in range(count):
        p = (
            Ether(src=ATTACKER_MAC, dst=HOST_MAC)
            / ARP(op=2, hwsrc=ATTACKER_MAC, psrc=GW_IP, hwdst=HOST_MAC, pdst=HOST_IP)
        )
        p.time = t + i * 1.0
        out.append(p)
    return out


def port_scan(t: float, target: str = PEER_IP, ports: range = range(1, 151)) -> list:
    """SYN scan: one probe every 20 ms; closed ports answer RST, a few open ports answer SYN-ACK."""
    out, open_ports = [], {22, 80, 443}
    for i, port in enumerate(ports):
        ts = t + i * 0.02
        syn = (Ether(src=ATTACKER_MAC, dst=PEER_MAC) / IP(src=ATTACKER_IP, dst=target)
               / TCP(sport=40000 + (i % 1000), dport=port, flags="S"))
        flags = "SA" if port in open_ports else "RA"
        rep = (Ether(src=PEER_MAC, dst=ATTACKER_MAC) / IP(src=target, dst=ATTACKER_IP)
               / TCP(sport=port, dport=40000 + (i % 1000), flags=flags))
        out += _stamp([syn, rep], ts, [0, 0.001])
    return out


def build_all(out_dir: Path, seed: int = 7) -> dict[str, Path]:
    random.seed(seed)
    out_dir.mkdir(parents=True, exist_ok=True)
    t0 = 1_793_000_000.0
    files = {
        "normal_traffic.pcap": normal_traffic(t0, 30),
        "arp_spoof.pcap": sorted(normal_traffic(t0, 10) + arp_spoof(t0 + 6), key=lambda p: p.time),
        "port_scan.pcap": sorted(normal_traffic(t0, 10) + port_scan(t0 + 4), key=lambda p: p.time),
        "demo_all.pcap": sorted(normal_traffic(t0, 40) + port_scan(t0 + 12) + arp_spoof(t0 + 28),
                                key=lambda p: p.time),
    }
    written = {}
    for name, pkts in files.items():
        path = out_dir / name
        wrpcap(str(path), pkts)
        written[name] = path
    return written


if __name__ == "__main__":
    target = Path(sys.argv[1] if len(sys.argv) > 1 else "pps_data/replay")
    for path in build_all(target).values():
        print(f"wrote {path}")

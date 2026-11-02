"""DecodeModule: turns raw Scapy packets into DecodedPacket records (PPS-F-010, PPS-F-011)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from scapy.layers.dns import DNS
from scapy.layers.http import HTTPRequest, HTTPResponse  # noqa: F401  (registers HTTP dissector on port 80)
from scapy.layers.inet import ICMP, IP, TCP, UDP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import ARP, Ether
from scapy.packet import Packet, Padding

from .applabel import DNS_PORTS, dns_info, http_from_payload

try:  # 802.11 frames appear only on monitor-mode captures
    from scapy.layers.dot11 import Dot11, Dot11Beacon, Dot11Elt, RadioTap
except Exception:  # pragma: no cover
    Dot11 = Dot11Beacon = Dot11Elt = RadioTap = None  # type: ignore

TCP_FLAG_NAMES = [
    ("F", "FIN"),
    ("S", "SYN"),
    ("R", "RST"),
    ("P", "PSH"),
    ("A", "ACK"),
    ("U", "URG"),
]


@dataclass
class DecodedPacket:
    seq: int
    ts: float
    length: int
    protocol: str  # highest recognised protocol, e.g. "DNS", "TCP", "ARP"
    app_proto: str | None = None  # "DNS" | "HTTP" | None (PPS-F-011)
    src_mac: str | None = None
    dst_mac: str | None = None
    src_ip: str | None = None
    dst_ip: str | None = None
    src_port: int | None = None
    dst_port: int | None = None
    tcp_flags: str | None = None
    info: str = ""
    protos: list[str] = field(
        default_factory=list
    )  # lower-case protocol names present, used by filters
    layers: list[dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    def summary(self) -> dict[str, Any]:
        """Compact form for the live table (layers omitted)."""
        d = self.to_dict()
        d.pop("layers")
        return d


def _flags(tcp: TCP) -> str:
    f = str(tcp.flags)
    return ",".join(name for letter, name in TCP_FLAG_NAMES if letter in f)


def decode(pkt: Packet, seq: int = 0) -> DecodedPacket:
    """Decode one packet. Never raises on malformed input; unknown parts are reported as Raw."""
    d = DecodedPacket(
        seq=seq, ts=float(getattr(pkt, "time", 0.0)), length=len(pkt), protocol="UNKNOWN"
    )
    try:
        _decode_into(pkt, d)
    except Exception as exc:  # malformed frame (TC-Rob-01): keep what we have
        d.layers.append({"proto": "Error", "fields": {"error": f"{type(exc).__name__}: {exc}"}})
        if not d.info:
            d.info = "Malformed packet"
    names = {
        layer["proto"].lower() for layer in d.layers if layer["proto"] not in ("Data", "Error")
    }
    if d.app_proto:
        names.add(d.app_proto.lower())
    if names & {"ipv4", "ipv6"}:
        names.add("ip")
    d.protos = sorted(names)
    return d


def _decode_into(pkt: Packet, d: DecodedPacket) -> None:
    layers = d.layers

    if RadioTap is not None and pkt.haslayer(Dot11):
        dot = pkt[Dot11]
        f = {
            "type": int(dot.type),
            "subtype": int(dot.subtype),
            "addr1": dot.addr1,
            "addr2": dot.addr2,
            "addr3": dot.addr3,
        }
        if pkt.haslayer(Dot11Beacon):
            ssid = ""
            elt = pkt.getlayer(Dot11Elt)
            if elt is not None and elt.ID == 0:
                ssid = elt.info.decode(errors="replace")
            f["ssid"] = ssid
            d.info = f"Beacon SSID={ssid!r} BSSID={dot.addr3}"
        layers.append({"proto": "802.11", "fields": f})
        d.protocol = "802.11"
        d.src_mac, d.dst_mac = dot.addr2, dot.addr1

    if pkt.haslayer(Ether):
        e = pkt[Ether]
        d.src_mac, d.dst_mac = e.src, e.dst
        layers.append(
            {"proto": "Ethernet", "fields": {"src": e.src, "dst": e.dst, "type": hex(e.type)}}
        )
        d.protocol = "Ethernet"

    if pkt.haslayer(ARP):
        a = pkt[ARP]
        op = {1: "who-has", 2: "is-at"}.get(int(a.op), str(a.op))
        layers.append(
            {
                "proto": "ARP",
                "fields": {
                    "op": op,
                    "hwsrc": a.hwsrc,
                    "psrc": a.psrc,
                    "hwdst": a.hwdst,
                    "pdst": a.pdst,
                },
            }
        )
        d.protocol = "ARP"
        d.src_ip, d.dst_ip = a.psrc, a.pdst
        d.info = (
            f"Who has {a.pdst}? Tell {a.psrc}" if int(a.op) == 1 else f"{a.psrc} is at {a.hwsrc}"
        )
        return

    l4 = None
    if pkt.haslayer(IP):
        ip = pkt[IP]
        d.src_ip, d.dst_ip = ip.src, ip.dst
        layers.append(
            {
                "proto": "IPv4",
                "fields": {
                    "src": ip.src,
                    "dst": ip.dst,
                    "ttl": ip.ttl,
                    "proto": ip.proto,
                    "len": ip.len,
                    "id": ip.id,
                    "flags": str(ip.flags),
                },
            }
        )
        d.protocol = "IPv4"
    elif pkt.haslayer(IPv6):
        ip6 = pkt[IPv6]
        d.src_ip, d.dst_ip = ip6.src, ip6.dst
        layers.append(
            {
                "proto": "IPv6",
                "fields": {
                    "src": ip6.src,
                    "dst": ip6.dst,
                    "nh": ip6.nh,
                    "hlim": ip6.hlim,
                    "plen": ip6.plen,
                },
            }
        )
        d.protocol = "IPv6"

    if pkt.haslayer(TCP):
        t = pkt[TCP]
        l4 = t
        d.src_port, d.dst_port = int(t.sport), int(t.dport)
        d.tcp_flags = _flags(t)
        layers.append(
            {
                "proto": "TCP",
                "fields": {
                    "sport": t.sport,
                    "dport": t.dport,
                    "seq": t.seq,
                    "ack": t.ack,
                    "flags": d.tcp_flags,
                    "window": t.window,
                },
            }
        )
        d.protocol = "TCP"
        d.info = f"{t.sport} -> {t.dport} [{d.tcp_flags}]"
    elif pkt.haslayer(UDP):
        u = pkt[UDP]
        l4 = u
        d.src_port, d.dst_port = int(u.sport), int(u.dport)
        layers.append(
            {"proto": "UDP", "fields": {"sport": u.sport, "dport": u.dport, "len": u.len}}
        )
        d.protocol = "UDP"
        d.info = f"{u.sport} -> {u.dport} len={u.len if u.len is not None else len(u)}"
    elif pkt.haslayer(ICMP):
        ic = pkt[ICMP]
        layers.append({"proto": "ICMP", "fields": {"type": ic.type, "code": ic.code}})
        d.protocol = "ICMP"
        d.info = ic.sprintf("%type%")
        return
    elif d.protocol in ("IPv6",) and pkt.lastlayer().name.startswith("ICMPv6"):
        last = pkt.lastlayer()
        layers.append({"proto": "ICMPv6", "fields": {"type": getattr(last, "type", None)}})
        d.protocol = "ICMPv6"
        d.info = last.name
        return

    if l4 is None:
        if not d.info:
            d.info = pkt.summary()
        return

    # ---- application layer labelling (PPS-F-011) ----
    if pkt.haslayer(DNS) and (d.src_port in DNS_PORTS or d.dst_port in DNS_PORTS):
        info, f = dns_info(pkt[DNS])
        layers.append({"proto": "DNS", "fields": f})
        d.protocol = d.app_proto = "DNS"
        d.info = info
        return

    # Full L7 bytes. Scapy may split HTTP into header and body layers,
    # so read the whole payload.
    # minus Ethernet padding on short frames
    payload = bytes(l4.payload)
    pad = l4.getlayer(Padding)
    if pad is not None:
        payload = payload[: len(payload) - len(bytes(pad))]
    http = http_from_payload(payload) if payload else None
    if http:
        info, f = http
        layers.append({"proto": "HTTP", "fields": f})
        d.protocol = d.app_proto = "HTTP"
        d.info = info
        return
    if payload:
        layers.append({"proto": "Data", "fields": {"length": len(payload)}})

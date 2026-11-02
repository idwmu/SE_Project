"""Display filters (PPS-F-021, PPS-F-022).

Grammar (case-insensitive keywords):
    expr    := and_e (("or" | "||") and_e)*
    and_e   := not_e (("and" | "&&") not_e)*
    not_e   := ("not" | "!") not_e | atom
    atom    := "(" expr ")" | field OP value | protocol
    OP      := == | != | > | < | >= | <= | contains

Fields: ip.src ip.dst ip.addr  eth.src eth.dst mac  port src.port dst.port tcp.port udp.port
        proto  len  info  tcp.flags
Protocols (bare words): tcp udp icmp icmpv6 arp dns http ipv4 ipv6 ip 802.11
Examples:
    ip.addr == 192.168.1.10 and (dns or http)
    tcp.port == 443 && !ip.src == 10.0.0.1
    mac == aa:bb:cc:dd:ee:ff or info contains "GET"
"""

from __future__ import annotations

import re
from collections.abc import Callable
from typing import Any

Pred = Callable[[dict[str, Any]], bool]


class FilterError(ValueError):
    pass


TOKEN_RE = re.compile(
    r"""\s*(?:
        (?P<lp>\()|(?P<rp>\))|
        (?P<op>==|!=|>=|<=|>|<)|
        (?P<and>&&)|(?P<or>\|\|)|(?P<bang>!)|
        "(?P<str>[^"]*)"|
        (?P<word>[A-Za-z0-9_.:\-/]+)
    )""",
    re.VERBOSE,
)

PROTOCOLS = {
    "tcp", "udp", "icmp", "icmpv6", "arp", "dns", "http", "ipv4", "ipv6", "ip", "802.11"
}
FIELDS = {
    "ip.src", "ip.dst", "ip.addr", "eth.src", "eth.dst", "mac", "port", "src.port",
    "dst.port", "tcp.port", "udp.port", "proto", "protocol", "len", "length", "info",
    "tcp.flags",
}


def _tokenize(text: str) -> list[tuple[str, str, int]]:
    pos, out = 0, []
    text = text.rstrip()
    while pos < len(text):
        m = TOKEN_RE.match(text, pos)
        if not m or m.end() == pos:
            raise FilterError(f"Unexpected character at position {pos}: {text[pos]!r}")
        kind = m.lastgroup or ""
        val = m.group(kind)
        start = m.start(kind)
        if kind == "word":
            low = val.lower()
            if low in ("and", "or", "not", "contains"):
                kind, val = low, low
        out.append((kind, val, start))
        pos = m.end()
    return out


def _layer_names(p: dict[str, Any]) -> set[str]:
    names = set(p.get("protos") or [])
    names.add(str(p.get("protocol", "")).lower())
    return names


def _values(p: dict[str, Any], fld: str) -> list[Any]:
    if fld.startswith("ip.") and "ip" not in _layer_names(p):
        return []  # like Wireshark, ip.* never matches ARP or other non-IP frames
    if fld == "ip.src":
        return [p.get("src_ip")]
    if fld == "ip.dst":
        return [p.get("dst_ip")]
    if fld == "ip.addr":
        return [p.get("src_ip"), p.get("dst_ip")]
    if fld == "eth.src":
        return [p.get("src_mac")]
    if fld == "eth.dst":
        return [p.get("dst_mac")]
    if fld == "mac":
        return [p.get("src_mac"), p.get("dst_mac")]
    if fld == "port":
        return [p.get("src_port"), p.get("dst_port")]
    if fld == "src.port":
        return [p.get("src_port")]
    if fld == "dst.port":
        return [p.get("dst_port")]
    if fld in ("tcp.port", "udp.port"):
        names = _layer_names(p)
        return [p.get("src_port"), p.get("dst_port")] if fld.split(".")[0] in names else []
    if fld in ("proto", "protocol"):
        return list(_layer_names(p))
    if fld in ("len", "length"):
        return [p.get("length")]
    if fld == "info":
        return [p.get("info")]
    if fld == "tcp.flags":
        return [p.get("tcp_flags")]
    raise FilterError(f"Unknown field {fld!r}")  # pragma: no cover


def _norm(v: Any) -> Any:
    return v.lower() if isinstance(v, str) else v


def _compare(op: str, actual: Any, wanted: str) -> bool:
    if actual is None:
        return False
    if op == "contains":
        return wanted.lower() in str(actual).lower()
    if isinstance(actual, (int, float)):
        try:
            w: Any = float(wanted)
        except ValueError:
            return False
        a: Any = float(actual)
    else:
        a, w = _norm(str(actual)), _norm(wanted)
    try:
        return {"==": a == w, "!=": a != w, ">": a > w, "<": a < w, ">=": a >= w, "<=": a <= w}[op]
    except TypeError:
        return False


class _Parser:
    def __init__(self, tokens: list[tuple[str, str, int]]):
        self.t = tokens
        self.i = 0

    def peek(self) -> tuple[str, str, int] | None:
        return self.t[self.i] if self.i < len(self.t) else None

    def take(self, *kinds: str) -> tuple[str, str, int]:
        tok = self.peek()
        if tok is None:
            names = {
                "rp": "')'", "lp": "'('", "word": "a value", "str": "a value",
                "op": "an operator", "contains": "an operator",
            }
            wanted = sorted({names.get(k, k) for k in kinds})
            raise FilterError(f"Unexpected end of filter, expected {' or '.join(wanted)}")
        if tok[0] not in kinds:
            raise FilterError(f"Unexpected {tok[1]!r} at position {tok[2]}")
        self.i += 1
        return tok

    def parse(self) -> Pred:
        pred = self.expr()
        if self.peek() is not None:
            tok = self.peek()
            raise FilterError(f"Unexpected {tok[1]!r} at position {tok[2]}")  # type: ignore[index]
        return pred

    def expr(self) -> Pred:
        parts = [self.and_e()]
        while (tok := self.peek()) and tok[0] == "or":
            self.i += 1
            parts.append(self.and_e())
        return parts[0] if len(parts) == 1 else (lambda p, ps=parts: any(f(p) for f in ps))

    def and_e(self) -> Pred:
        parts = [self.not_e()]
        while (tok := self.peek()) and tok[0] == "and":
            self.i += 1
            parts.append(self.not_e())
        return parts[0] if len(parts) == 1 else (lambda p, ps=parts: all(f(p) for f in ps))

    def not_e(self) -> Pred:
        tok = self.peek()
        if tok and tok[0] in ("not", "bang"):
            self.i += 1
            inner = self.not_e()
            return lambda p: not inner(p)
        return self.atom()

    def atom(self) -> Pred:
        tok = self.take("lp", "word")
        if tok[0] == "lp":
            inner = self.expr()
            self.take("rp")
            return inner
        word = tok[1].lower()
        nxt = self.peek()
        if nxt and nxt[0] in ("op", "contains"):
            if word not in FIELDS:
                raise FilterError(f"Unknown field {tok[1]!r} at position {tok[2]}")
            op = self.take("op", "contains")[1]
            val = self.take("word", "str")[1]
            ip_field = word in ("ip.src", "ip.dst", "ip.addr")
            if op != "contains" and ip_field and not _looks_like_ip(val):
                raise FilterError(f"{val!r} is not an IP address")
            return lambda p, f=word, o=op, v=val: any(_compare(o, a, v) for a in _values(p, f))
        if word in PROTOCOLS:
            return lambda p, w=word: w in _layer_names(p)
        if word in FIELDS:
            raise FilterError(f"Field {tok[1]!r} needs a comparison, e.g. {tok[1]} == value")
        raise FilterError(f"Unknown protocol or field {tok[1]!r} at position {tok[2]}")


def _looks_like_ip(v: str) -> bool:
    ipv4 = re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", v)
    ipv6 = ":" in v and re.fullmatch(r"[0-9a-fA-F:]+", v)
    return bool(ipv4 or ipv6)


def compile_filter(text: str | None) -> Pred:
    """Compile a display filter. Empty filter matches everything. Raises FilterError."""
    if not text or not text.strip():
        return lambda p: True
    return _Parser(_tokenize(text)).parse()

"""Application-layer labelling for DNS and HTTP (PPS-F-011).

DNS is recognised on its well-known ports; HTTP by its request/response signature on any port.
"""

from __future__ import annotations

from typing import Any

from scapy.layers.dns import DNS

DNS_PORTS = {53, 5353}
HTTP_METHODS = (b"GET ", b"POST ", b"PUT ", b"DELETE ", b"HEAD ", b"OPTIONS ", b"PATCH ")


def dns_info(dns: DNS) -> tuple[str, dict[str, Any]]:
    qname = ""
    qtype = ""
    if dns.qd:
        q = dns.qd[0] if isinstance(dns.qd, list) else dns.qd
        qname = (
            q.qname.decode(errors="replace").rstrip(".")
            if isinstance(q.qname, bytes)
            else str(q.qname)
        )
        qtype = q.sprintf("%qtype%")
    answers = []
    for i in range(dns.ancount or 0):
        try:
            rr = dns.an[i]
            rdata = rr.rdata
            answers.append(
                rdata.decode(errors="replace") if isinstance(rdata, bytes) else str(rdata)
            )
        except Exception:
            break
    kind = "response" if dns.qr else "query"
    info = f"DNS {kind} {qtype} {qname}".strip()
    if answers:
        info += " -> " + ", ".join(answers[:3])
    return info, {"id": dns.id, "qr": kind, "qname": qname, "qtype": qtype, "answers": answers}


def http_from_payload(payload: bytes) -> tuple[str, dict[str, Any]] | None:
    """Signature-based HTTP detection for any port."""
    if payload.startswith(HTTP_METHODS):
        line = payload.split(b"\r\n", 1)[0].decode(errors="replace")
        parts = line.split(" ")
        fields = {
            "method": parts[0],
            "path": parts[1] if len(parts) > 1 else "",
            "version": parts[-1],
        }
        host = next((h for h in payload.split(b"\r\n") if h.lower().startswith(b"host:")), b"")
        if host:
            fields["host"] = host.split(b":", 1)[1].strip().decode(errors="replace")
        return line, fields
    if payload.startswith(b"HTTP/1."):
        line = payload.split(b"\r\n", 1)[0].decode(errors="replace")
        parts = line.split(" ", 2)
        return line, {
            "version": parts[0],
            "status": parts[1] if len(parts) > 1 else "",
            "reason": parts[2] if len(parts) > 2 else "",
        }
    return None

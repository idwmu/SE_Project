"""TC-Dec-02 at function level: DNS and HTTP labelling helpers."""

from scapy.layers.dns import DNS, DNSQR, DNSRR

from pps.applabel import dns_info, http_from_payload


def test_dns_query_info():
    info, f = dns_info(DNS(bytes(DNS(id=7, rd=1, qd=DNSQR(qname="pes.edu")))))
    assert info == "DNS query A pes.edu"
    assert f["id"] == 7 and f["qr"] == "query" and f["answers"] == []


def test_dns_response_answers():
    pkt = DNS(
        bytes(DNS(qr=1, qd=DNSQR(qname="a.test"), an=DNSRR(rrname="a.test", rdata="203.0.113.5")))
    )
    info, f = dns_info(pkt)
    assert f["qr"] == "response" and f["answers"] == ["203.0.113.5"]
    assert info.endswith("-> 203.0.113.5")


def test_http_request_signature():
    line, f = http_from_payload(b"POST /login HTTP/1.1\r\nHost: example.test\r\n\r\nuser=x")
    assert line == "POST /login HTTP/1.1"
    assert f == {"method": "POST", "path": "/login", "version": "HTTP/1.1", "host": "example.test"}


def test_http_response_signature():
    line, f = http_from_payload(b"HTTP/1.1 301 Moved Permanently\r\nLocation: /\r\n\r\n")
    assert f["status"] == "301" and f["reason"] == "Moved Permanently"


def test_not_http():
    assert http_from_payload(b"\x16\x03\x01\x02\x00") is None
    assert http_from_payload(b"GETTING STARTED") is None

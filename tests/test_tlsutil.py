"""TC-Sec-02: TLS certificate management and an encrypted control API (PPS-SR-002)."""

import datetime as dt
import hashlib
import http.client
import json
import logging
import os
import queue
import socket
import ssl
import subprocess
import sys
import threading
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from pps import tlsutil
from pps.tlsutil import TlsError

NOW = dt.datetime(2026, 11, 11, 12, 0, tzinfo=dt.timezone.utc)
DNS = ["localhost", "pps.local"]
IPS = ["127.0.0.1", "192.168.1.50"]
REPO = Path(__file__).resolve().parents[1]
posix_only = pytest.mark.skipif(os.name != "posix", reason="POSIX file modes")


def ensure(directory, **kw):
    kw.setdefault("dns_names", DNS)
    kw.setdefault("ip_addresses", IPS)
    kw.setdefault("now", NOW)
    return tlsutil.ensure_cert(directory, **kw)


def load_cert(path):
    return x509.load_pem_x509_certificate(Path(path).read_bytes())


def spki(public_key):
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def key_matches_cert(files):
    key = serialization.load_pem_private_key(files.key.read_bytes(), password=None)
    return spki(key.public_key()) == spki(load_cert(files.cert).public_key())


def make_supplied(directory, *, days=365, org="Example Corp CA", now=NOW, san=("example.test",)):
    """A certificate PPS did *not* generate, as an administrator would supply."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, org),
            x509.NameAttribute(NameOID.COMMON_NAME, "x"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in san]), critical=False)
        .sign(key, hashes.SHA256())
    )
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (directory / "key.pem").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return directory / "cert.pem", directory / "key.pem"


# ------------------------------------------------------------------ generated certificate
def test_generated_certificate_properties(tmp_path):
    files = ensure(tmp_path / "tls")
    cert = load_cert(files.cert)

    assert cert.subject == cert.issuer  # self-signed
    assert isinstance(cert.public_key(), ec.EllipticCurvePublicKey)
    assert cert.public_key().curve.name == "secp256r1"
    assert cert.signature_hash_algorithm.name == "sha256"
    assert cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    key_usage = cert.extensions.get_extension_for_class(x509.KeyUsage).value
    assert key_usage.digital_signature and not key_usage.key_cert_sign
    eku = cert.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert list(eku) == [ExtendedKeyUsageOID.SERVER_AUTH]

    san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert set(san.get_values_for_type(x509.DNSName)) == set(DNS)
    assert {str(i) for i in san.get_values_for_type(x509.IPAddress)} == set(IPS)

    assert cert.not_valid_before_utc < NOW < cert.not_valid_after_utc
    assert (cert.not_valid_after_utc - NOW).days == tlsutil.VALID_DAYS

    der = cert.public_bytes(serialization.Encoding.DER)
    raw = hashlib.sha256(der).hexdigest().upper()
    assert files.fingerprint == ":".join(raw[i : i + 2] for i in range(0, 64, 2))


@posix_only
def test_private_key_is_not_readable_by_others(tmp_path):
    files = ensure(tmp_path / "tls")
    assert files.key.stat().st_mode & 0o777 == 0o600
    assert files.cert.stat().st_mode & 0o777 == 0o644
    assert files.key.parent.stat().st_mode & 0o777 == 0o700
    assert sorted(p.name for p in files.key.parent.iterdir()) == ["cert.pem", "key.pem"]


@posix_only
def test_existing_directory_permissions_are_left_alone(tmp_path):
    d = tmp_path / "tls"
    d.mkdir(mode=0o755)
    d.chmod(0o755)
    ensure(d)
    assert d.stat().st_mode & 0o777 == 0o755


def test_existing_valid_certificate_is_reused_untouched(tmp_path):
    first = ensure(tmp_path / "tls")
    before = (first.cert.read_bytes(), first.key.read_bytes(), first.cert.stat().st_mtime_ns)
    again = ensure(tmp_path / "tls", now=NOW + dt.timedelta(days=100))
    assert again.fingerprint == first.fingerprint
    after = (again.cert.read_bytes(), again.key.read_bytes(), again.cert.stat().st_mtime_ns)
    assert after == before


def test_key_matches_certificate(tmp_path):
    assert key_matches_cert(ensure(tmp_path / "tls"))


# ------------------------------------------------------------------ regeneration of PPS-made certs
@pytest.mark.parametrize(
    ("days_later", "regenerated"),
    [(300, False), (334, False), (336, True), (364, True), (400, True)],
)
def test_renewal_window(tmp_path, days_later, regenerated):
    first = ensure(tmp_path / "tls")
    later = ensure(tmp_path / "tls", now=NOW + dt.timedelta(days=days_later))
    assert (later.fingerprint != first.fingerprint) is regenerated
    if regenerated:  # the new certificate is valid at the time it was issued
        cert, at = load_cert(later.cert), NOW + dt.timedelta(days=days_later)
        assert cert.not_valid_before_utc < at < cert.not_valid_after_utc


@pytest.mark.parametrize(
    "change",
    [
        {"ip_addresses": IPS + ["10.0.0.9"]},
        {"dns_names": DNS + ["other.local"]},
        {"extra_hosts": ["10.1.2.3"]},
        {"extra_hosts": ["myhost.example"]},
    ],
    ids=["new-ip", "new-dns", "bind-ip", "bind-name"],
)
def test_regenerates_when_the_names_clients_use_change(tmp_path, change):
    first = ensure(tmp_path / "tls")
    second = ensure(tmp_path / "tls", **change)
    assert second.fingerprint != first.fingerprint
    ensure(tmp_path / "tls", **change)  # and then it is stable again
    assert ensure(tmp_path / "tls", **change).fingerprint == second.fingerprint


def test_wildcard_and_junk_bind_hosts_do_not_change_the_certificate(tmp_path):
    first = ensure(tmp_path / "tls")
    for hosts in (["0.0.0.0"], ["::"], [""], ["bad host!;"], ["127.0.0.1"], ["LOCALHOST"]):
        assert ensure(tmp_path / "tls", extra_hosts=hosts).fingerprint == first.fingerprint


def test_replaced_key_is_detected_and_pair_regenerated(tmp_path):
    first = ensure(tmp_path / "tls")
    other = ec.generate_private_key(ec.SECP256R1())
    first.key.write_bytes(
        other.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    second = ensure(tmp_path / "tls")
    assert second.fingerprint != first.fingerprint
    assert key_matches_cert(second)


def test_interrupted_run_leaving_only_our_certificate_recovers(tmp_path):
    first = ensure(tmp_path / "tls")
    first.key.unlink()
    second = ensure(tmp_path / "tls")
    assert second.key.exists() and second.fingerprint != first.fingerprint


# ------------------------------------------------------------------ never overwrite others' files
def test_lone_private_key_is_never_overwritten(tmp_path):
    d = tmp_path / "tls"
    d.mkdir()
    (d / "key.pem").write_text("precious key material")
    with pytest.raises(TlsError, match="without"):
        ensure(d)
    assert (d / "key.pem").read_text() == "precious key material"
    assert not (d / "cert.pem").exists()


def test_lone_foreign_certificate_is_never_overwritten(tmp_path):
    d = tmp_path / "tls"
    cert_path, key_path = make_supplied(d)
    key_path.unlink()
    before = cert_path.read_bytes()
    with pytest.raises(TlsError, match="without"):
        ensure(d)
    assert cert_path.read_bytes() == before


def encrypt_key_file(key_path):
    key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    protected = key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.BestAvailableEncryption(b"hunter2"),
    )
    key_path.write_bytes(protected)
    return protected


def test_unreadable_certificate_is_reported_not_replaced(tmp_path):
    """Without a readable certificate we cannot tell whether the files are ours."""
    first = ensure(tmp_path / "tls")
    first.cert.write_text("this is not PEM")
    with pytest.raises(TlsError, match="will not overwrite"):
        ensure(tmp_path / "tls")
    assert first.cert.read_text() == "this is not PEM"


@pytest.mark.parametrize("damage", ["garbage", "encrypted", "empty"])
def test_our_own_certificate_with_an_unreadable_key_self_heals(tmp_path, damage):
    first = ensure(tmp_path / "tls")
    if damage == "garbage":
        first.key.write_text("this is not PEM")
    elif damage == "encrypted":
        encrypt_key_file(first.key)
    else:
        first.key.write_bytes(b"")
    second = ensure(tmp_path / "tls")
    assert second.fingerprint != first.fingerprint
    assert key_matches_cert(second)


@pytest.mark.parametrize("damage", ["garbage", "encrypted"])
def test_supplied_certificate_with_an_unreadable_key_is_never_replaced(tmp_path, damage):
    cert_path, key_path = make_supplied(tmp_path / "tls")
    if damage == "garbage":
        key_path.write_text("this is not PEM")
    else:
        encrypt_key_file(key_path)
    before = (cert_path.read_bytes(), key_path.read_bytes())
    with pytest.raises(TlsError, match="will not overwrite"):
        ensure(tmp_path / "tls")
    assert (cert_path.read_bytes(), key_path.read_bytes()) == before


def test_encrypted_supplied_key_gets_a_specific_message(tmp_path):
    _, key_path = make_supplied(tmp_path / "tls")
    encrypt_key_file(key_path)
    with pytest.raises(TlsError, match="Encrypted keys are not supported"):
        ensure(tmp_path / "tls")


def test_stale_temp_files_do_not_interfere_and_none_are_left(tmp_path):
    d = tmp_path / "tls"
    d.mkdir()
    for name in ("cert.pem.tmp", "key.pem.tmp", ".key.pem.1.deadbeef.tmp"):
        (d / name).write_text("left by a crashed run")
    files = ensure(d)
    assert key_matches_cert(files)
    leftovers = sorted(p.name for p in d.iterdir() if p.name not in ("cert.pem", "key.pem"))
    assert leftovers == [".key.pem.1.deadbeef.tmp", "cert.pem.tmp", "key.pem.tmp"]


def test_real_processes_starting_together_do_not_crash(tmp_path):
    """Two PPS servers launched at once on one data folder (e.g. a service restart overlap)."""
    code = (
        "import sys, time\n"
        "from pathlib import Path\n"
        "from pps import tlsutil\n"
        "while time.time() < float(sys.argv[2]):\n"
        "    pass\n"  # release all processes at the same instant
        "tlsutil.ensure_cert(Path(sys.argv[1]), dns_names=['localhost'],\n"
        "                    ip_addresses=['127.0.0.1'])\n"
    )
    start_at = time.time() + 3
    procs = [
        subprocess.Popen(
            [sys.executable, "-c", code, str(tmp_path / "tls"), str(start_at)],
            cwd=REPO, stderr=subprocess.PIPE, text=True,
        )
        for _ in range(6)
    ]  # fmt: skip
    results = [(p.wait(60), p.stderr.read()) for p in procs]
    assert [rc for rc, _ in results] == [0] * 6, results
    files = tlsutil.ensure_cert(
        tmp_path / "tls", dns_names=["localhost"], ip_addresses=["127.0.0.1"]
    )
    assert key_matches_cert(files)


def test_processes_starting_together_do_not_crash_and_settle_on_a_valid_pair(tmp_path):
    errors = []

    def start():
        try:
            ensure(tmp_path / "tls")
        except Exception as exc:  # noqa: BLE001
            errors.append(exc)

    threads = [threading.Thread(target=start) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert key_matches_cert(ensure(tmp_path / "tls"))  # a racing pair at worst self-heals


def test_supplied_certificate_is_used_as_is(tmp_path, caplog):
    d = tmp_path / "tls"
    cert_path, key_path = make_supplied(d, days=10)  # inside the renewal window, wrong names
    before = (cert_path.read_bytes(), key_path.read_bytes())
    with caplog.at_level(logging.WARNING, logger="pps.tls"):
        files = ensure(d)
    assert files.fingerprint == tlsutil.fingerprint(load_cert(cert_path))
    assert (cert_path.read_bytes(), key_path.read_bytes()) == before
    assert "renew it" in caplog.text


def test_certificate_from_the_original_reference_implementation_is_kept(tmp_path, caplog):
    """Earlier PPS versions wrote cert.pem/key.pem (825 days, CN pps.local); keep using them."""
    d = tmp_path / "tls"
    cert_path, key_path = make_supplied(
        d, org="Pocket Packet Sniffer", days=825, san=("localhost", "pps.local")
    )
    before = (cert_path.read_bytes(), key_path.read_bytes())
    files = ensure(d)  # the SAN lacks the new LAN IP, but this is not ours to rewrite
    assert files.fingerprint == tlsutil.fingerprint(load_cert(cert_path))
    assert (cert_path.read_bytes(), key_path.read_bytes()) == before


def test_supplied_certificate_problems_are_errors_not_silent_replacement(tmp_path):
    d = tmp_path / "expired"
    cert_path, key_path = make_supplied(d, days=1)
    before = cert_path.read_bytes()
    with pytest.raises(TlsError, match="expired"):
        ensure(d, now=NOW + dt.timedelta(days=5))
    assert cert_path.read_bytes() == before

    d2 = tmp_path / "mismatch"
    cert2, key2 = make_supplied(d2)
    other, _ = make_supplied(tmp_path / "elsewhere")
    cert2.write_bytes(other.read_bytes())
    with pytest.raises(TlsError, match="does not match"):
        ensure(d2)


# ------------------------------------------------------------------ names
@pytest.fixture
def no_dns(monkeypatch):
    """Name resolution can stall on a device with broken DNS, so it must never be used."""

    def forbidden(*args, **kwargs):
        raise AssertionError("local_names() must not resolve host names")

    monkeypatch.setattr(socket, "getaddrinfo", forbidden)
    monkeypatch.setattr(socket, "gethostbyname", forbidden)
    monkeypatch.setattr(socket, "gethostbyname_ex", forbidden)


def test_local_names_include_loopback_hostname_mdns_and_wifi_without_using_dns(
    monkeypatch, no_dns
):
    monkeypatch.setattr(socket, "gethostname", lambda: "raspberrypi")
    monkeypatch.setattr(
        tlsutil, "_wireless_addresses", lambda: ["10.0.0.5", "fe80::1", "0.0.0.0"]
    )
    dns, ips = tlsutil.local_names()
    assert {"localhost", "raspberrypi", "raspberrypi.local"} <= set(dns)
    assert {"127.0.0.1", "::1", "10.0.0.5"} <= set(ips)
    assert not {"0.0.0.0", "fe80::1"} & set(ips)  # unusable addresses are filtered


def test_wireless_addresses_come_from_up_wifi_interfaces_only(monkeypatch):
    from pps import interfaces

    def info(name, *, up=True, wireless=False, ips=()):
        return interfaces.InterfaceInfo(
            name=name, description=name, mac=None, ips=tuple(ips), is_up=up, is_loopback=False,
            is_wireless=wireless, monitor_capable=None, in_monitor_mode=False,
        )  # fmt: skip

    monkeypatch.setattr(
        interfaces,
        "list_interfaces",
        lambda: [
            info("wlan0", wireless=True, ips=["10.42.0.1", "2001:db8::1"]),
            info("wlan1", up=False, wireless=True, ips=["10.9.9.9"]),
            info("eth0", ips=["192.168.1.9"]),
            info("docker0", ips=["172.17.0.1"]),
        ],
    )
    assert tlsutil._wireless_addresses() == ["10.42.0.1"]  # IPv4 only: v6 privacy addresses rotate


def test_odd_hostnames_and_interface_failures_are_tolerated(monkeypatch, no_dns):
    from pps import interfaces

    def broken():
        raise interfaces.InterfaceError("no backend")

    monkeypatch.setattr(interfaces, "list_interfaces", broken)
    monkeypatch.setattr(socket, "gethostname", lambda: "bad host!;")
    dns, ips = tlsutil.local_names()
    assert dns == ["localhost"] and "127.0.0.1" in ips
    monkeypatch.setattr(socket, "gethostname", lambda: "pps-box")
    assert "pps-box" in tlsutil.local_names()[0]


@pytest.mark.parametrize(
    ("hosts", "dns", "ips"),
    [
        (["192.168.0.2", "Pps.Example", "[::1]"], ["pps.example"], ["192.168.0.2", "::1"]),
        (["0.0.0.0", "::", "", "  ", "fe80::1", "224.0.0.1", "no spaces", "x;y"], [], []),
    ],
)
def test_host_name_classification(hosts, dns, ips):
    assert tlsutil._host_names(hosts) == (dns, ips)


# ------------------------------------------------------------------ a real TLS handshake
class TlsServer:
    """Minimal TLS server using the generated certificate; accepts, handshakes, closes."""

    def __init__(self, files):
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.ctx.load_cert_chain(files.cert, files.key)
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(5)
        self.port = self.sock.getsockname()[1]
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while True:
            try:
                raw, _ = self.sock.accept()
            except OSError:
                return
            try:
                self.ctx.wrap_socket(raw, server_side=True).close()
            except (ssl.SSLError, OSError):
                raw.close()

    def close(self):
        self.sock.close()


@pytest.fixture
def tls_server(tmp_path):
    files = tlsutil.ensure_cert(tmp_path / "tls")  # real local names, real clock
    server = TlsServer(files)
    yield server, files
    server.close()


def connect(port, hostname, cafile=None):
    ctx = ssl.create_default_context(cafile=cafile)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
            return tls.version(), tls.getpeercert(binary_form=True)


@pytest.mark.parametrize("hostname", ["localhost", "127.0.0.1", "::1"])
def test_clients_that_trust_the_certificate_connect_over_modern_tls(tls_server, hostname):
    server, files = tls_server
    version, der = connect(server.port, hostname, cafile=str(files.cert))
    assert version in ("TLSv1.2", "TLSv1.3")
    assert hashlib.sha256(der).hexdigest().upper() == files.fingerprint.replace(":", "")


def test_self_signed_certificate_is_not_trusted_by_default(tls_server):
    """The honest limitation: without pinning/importing it, clients rightly refuse it."""
    server, _ = tls_server
    with pytest.raises(ssl.SSLCertVerificationError):
        connect(server.port, "localhost")


def test_certificate_is_rejected_for_a_name_it_does_not_cover(tls_server):
    server, files = tls_server
    with pytest.raises(ssl.SSLCertVerificationError, match="Hostname mismatch|IP address mismatch"):
        connect(server.port, "evil.example", cafile=str(files.cert))


# ------------------------------------------------------------------ end to end: python -m pps
def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class Server:
    def __init__(self, tmp_path, *args):
        self.port = free_port()
        self.data = tmp_path / "data"
        self.proc = subprocess.Popen(
            [sys.executable, "-m", "pps", "--host", "127.0.0.1", "--port", str(self.port),
             "--data-dir", str(self.data), "--pin", "424242", *args],
            cwd=REPO, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
        )  # fmt: skip
        self.out, self.err = [], []
        self._lines = queue.Queue()
        for stream, sink in ((self.proc.stdout, self.out), (self.proc.stderr, self.err)):
            threading.Thread(target=self._drain, args=(stream, sink), daemon=True).start()

    def _drain(self, stream, sink):
        for line in stream:
            sink.append(line.rstrip("\n"))
            self._lines.put(line)

    def wait_ready(self, timeout=40):
        end = time.time() + timeout
        while time.time() < end:
            if self.proc.poll() is not None:
                raise AssertionError(f"server exited early ({self.proc.returncode}): {self.err}")
            try:
                socket.create_connection(("127.0.0.1", self.port), timeout=0.5).close()
                return self
            except OSError:
                time.sleep(0.1)
        raise AssertionError(f"server did not start: out={self.out} err={self.err}")

    def banner(self):
        return "\n".join(self.out)

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()


@pytest.fixture
def run_server(tmp_path):
    servers = []

    def start(*args):
        s = Server(tmp_path, *args)
        servers.append(s)
        return s

    yield start
    for s in servers:
        s.stop()


def test_default_start_serves_the_api_only_over_tls(run_server):
    """AC-PPS-SR-002: the API is reachable over TLS and not in plaintext on the same port."""
    server = run_server().wait_ready()
    cert_path = server.data / "tls" / "cert.pem"

    banner_fp = next(ln for ln in server.out if "TLS cert" in ln).split("SHA-256 ")[1].strip()
    assert banner_fp == tlsutil.fingerprint(load_cert(cert_path))
    assert f"https://localhost:{server.port}/" in server.banner()

    ctx = ssl.create_default_context(cafile=str(cert_path))  # pinned: verifies chain and name
    for host in ("localhost", "127.0.0.1"):
        conn = http.client.HTTPSConnection(host, server.port, context=ctx, timeout=10)
        conn.request("GET", "/api/v1/auth/me")
        resp = conn.getresponse()
        body = json.loads(resp.read())
        conn.close()
        assert resp.status == 401 and body["error"]["code"]  # a real API answer, over TLS

    plain = http.client.HTTPConnection("127.0.0.1", server.port, timeout=5)
    with pytest.raises((http.client.HTTPException, OSError)):
        plain.request("GET", "/api/v1/auth/me")
        reply = plain.getresponse()
        reply.read()
        pytest.fail(f"plaintext HTTP got an answer: {reply.status}")  # must never happen
    plain.close()


def test_no_tls_flag_serves_plain_http_with_a_clear_warning(run_server):
    server = run_server("--no-tls").wait_ready()
    conn = http.client.HTTPConnection("127.0.0.1", server.port, timeout=10)
    conn.request("GET", "/api/v1/auth/me")
    assert conn.getresponse().status == 401
    conn.close()
    assert "TLS is off" in server.banner()
    assert "TLS cert" not in server.banner()
    assert not (server.data / "tls").exists()


def test_bad_tls_files_stop_startup_before_the_admin_password_is_created(run_server, tmp_path):
    tls_dir = tmp_path / "data" / "tls"
    tls_dir.mkdir(parents=True)
    (tls_dir / "cert.pem").write_text("not a certificate")
    (tls_dir / "key.pem").write_text("not a key")
    server = run_server()
    assert server.proc.wait(30) == 2
    time.sleep(0.2)
    assert any("TLS error" in ln for ln in server.err)
    assert not any("password" in ln.lower() for ln in server.out)  # the one-time password
    assert not (tmp_path / "data" / "pps.db").exists()  # nothing was created
    assert (tls_dir / "cert.pem").read_text() == "not a certificate"

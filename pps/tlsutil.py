"""TLS for the dashboard and control API (PPS-SR-002).

``ensure_cert()`` returns the certificate and key the server should use, creating a
**self-signed certificate for local demonstration** on first run.

What a self-signed certificate does and does not give you
---------------------------------------------------------
It encrypts traffic between the companion app and the device, which is what PPS-SR-002
asks for. It does **not** prove the device's identity: no certificate authority vouches
for it, so browsers warn and a client on the same network could present its own
self-signed certificate. A user should compare the SHA-256 fingerprint printed on the
device's console with the one the browser shows before accepting it, or import the
certificate as trusted. There is no revocation, and the key lives on the device's storage.

For anything beyond a demo, put a certificate issued by a real or private CA in
``<directory>/cert.pem`` and its key in ``<directory>/key.pem``. Files that PPS did
not generate are used as-is and never overwritten or regenerated.
This includes certificates created by earlier PPS versions, which are kept until they expire.

Generated certificates use an ECDSA P-256 key, are valid for one year, cover ``localhost``,
the loopback addresses, this machine's host name and its current LAN addresses, and are
re-issued automatically when close to expiry or when those names change (which changes the
fingerprint). The key file is created with mode 0600; on Windows file modes are not enforced.
"""

from __future__ import annotations

import datetime as dt
import ipaddress
import logging
import os
import re
import secrets
import socket
from collections.abc import Iterable
from pathlib import Path
from typing import NamedTuple

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

log = logging.getLogger("pps.tls")

CERT_NAME = "cert.pem"
KEY_NAME = "key.pem"
VALID_DAYS = 365
RENEW_BEFORE_DAYS = 30
# Marks certificates PPS generated, so it never replaces one an administrator supplied.
GENERATED_ORG = "Pocket Packet Sniffer (self-signed, local development)"

_HOSTNAME_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9.-]{0,250}[A-Za-z0-9])?$")


class TlsError(RuntimeError):
    """The certificate or key cannot be used and PPS will not overwrite it."""


class TlsFiles(NamedTuple):
    cert: Path
    key: Path
    fingerprint: str  # SHA-256 of the DER certificate, "AB:CD:..."


# ---------------------------------------------------------------- names
def _wireless_addresses() -> list[str]:
    """IPv4 addresses of up Wi-Fi interfaces: where a hotspot-mode device is reached.

    Other interfaces are left out on purpose (a fingerprint change for every container
    network that appears would be noise); pass such addresses with ``extra_hosts``.
    """
    try:
        from .interfaces import list_interfaces

        return [
            ip
            for iface in list_interfaces()
            if iface.is_up and iface.is_wireless
            for ip in iface.ips
            if "." in ip
        ]
    except Exception:  # optional enrichment: never let it block startup
        return []


def local_names() -> tuple[list[str], list[str]]:
    """DNS names and IP addresses a client might use to reach this device."""
    dns = ["localhost"]
    ips = {"127.0.0.1", "::1"}
    host = socket.gethostname().strip()
    if _HOSTNAME_RE.match(host):
        dns.append(host)
        if "." not in host:
            dns.append(f"{host}.local")  # mDNS, e.g. raspberrypi.local
    # No name resolution here: it can stall for seconds on a device with broken DNS.
    try:  # primary LAN address; a UDP connect sends no packets
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("192.0.2.1", 9))
            ips.add(s.getsockname()[0])
    except OSError:
        pass
    ips.update(_wireless_addresses())
    usable = []
    for text in ips:
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            continue
        if not (ip.is_unspecified or ip.is_multicast or ip.is_link_local):
            usable.append(str(ip))
    return sorted(set(dns)), sorted(usable)


# ---------------------------------------------------------------- generation
def generate_self_signed(
    dns_names: list[str],
    ip_addresses: list[str],
    *,
    now: dt.datetime | None = None,
    days: int = VALID_DAYS,
) -> tuple[bytes, bytes]:
    """Return ``(certificate_pem, private_key_pem)`` for a new self-signed server certificate."""
    now = now or dt.datetime.now(dt.timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, GENERATED_ORG),
            x509.NameAttribute(NameOID.COMMON_NAME, "Pocket Packet Sniffer"),
        ]
    )
    san = [x509.DNSName(n) for n in dns_names] + [
        x509.IPAddress(ipaddress.ip_address(i)) for i in ip_addresses
    ]
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(minutes=5))  # tolerate small clock differences
        .not_valid_after(now + dt.timedelta(days=days))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign=False,
                crl_sign=False,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM),
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        ),
    )


def _write_atomic(path: Path, data: bytes, mode: int) -> None:
    """Write via a temporary file created with its final permissions, then rename."""
    # Unique per process and call, so two PPS processes starting together cannot clash.
    tmp = path.with_name(f".{path.name}.{os.getpid()}.{secrets.token_hex(4)}.tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, mode)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
    finally:
        tmp.unlink(missing_ok=True)


# ---------------------------------------------------------------- inspection
def fingerprint(cert: x509.Certificate) -> str:
    raw = cert.fingerprint(hashes.SHA256()).hex().upper()
    return ":".join(raw[i : i + 2] for i in range(0, len(raw), 2))


def _is_ours(cert: x509.Certificate) -> bool:
    orgs = cert.subject.get_attributes_for_oid(NameOID.ORGANIZATION_NAME)
    return cert.subject == cert.issuer and any(o.value == GENERATED_ORG for o in orgs)


def _public_der(public_key) -> bytes:
    return public_key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )


def _san_values(cert: x509.Certificate) -> tuple[set[str], set[str]]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return set(), set()
    return (
        {n.lower() for n in san.get_values_for_type(x509.DNSName)},
        {str(i) for i in san.get_values_for_type(x509.IPAddress)},
    )


def _expires(cert: x509.Certificate) -> dt.datetime:
    return cert.not_valid_after_utc


def _load_pair(cert_path: Path, key_path: Path):
    """Parse an existing pair; raise TlsError naming the file if it is unusable.

    Returns ``(cert, None)`` when the certificate is one PPS generated but its key cannot be
    read: PPS never writes encrypted keys, so the pair is simply replaced.
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_path.read_bytes())
    except (ValueError, OSError) as exc:
        raise TlsError(
            f"Cannot read certificate {cert_path}: {exc}. "
            "PPS will not overwrite it; fix it, or delete both files to generate a new pair."
        ) from None
    try:
        key = serialization.load_pem_private_key(key_path.read_bytes(), password=None)
    except (ValueError, TypeError, OSError) as exc:
        if _is_ours(cert):
            return cert, None
        raise TlsError(
            f"Cannot read private key {key_path}: {exc}. Encrypted keys are not supported. "
            "PPS will not overwrite it; fix it, or delete both files to generate a new pair."
        ) from None
    return cert, key


def _needs_regeneration(
    cert: x509.Certificate, key, dns: list[str], ips: list[str], now: dt.datetime
) -> str | None:
    """Why a PPS-generated certificate should be replaced, or None if it is fine."""
    if _public_der(cert.public_key()) != _public_der(key.public_key()):
        return "certificate does not match its key"
    if now >= _expires(cert) - dt.timedelta(days=RENEW_BEFORE_DAYS):
        return "certificate is expired or close to expiry"
    have_dns, have_ips = _san_values(cert)
    missing = [n for n in dns if n.lower() not in have_dns] + [i for i in ips if i not in have_ips]
    if missing:
        return "certificate does not cover " + ", ".join(missing)
    return None


def _check_supplied(cert: x509.Certificate, key, now: dt.datetime, cert_path: Path) -> None:
    """Validate an administrator-supplied pair; it is never modified."""
    if _public_der(cert.public_key()) != _public_der(key.public_key()):
        raise TlsError(f"{cert_path} does not match its private key.")
    if now >= _expires(cert):
        raise TlsError(f"Certificate {cert_path} expired on {_expires(cert):%Y-%m-%d}.")
    if now >= _expires(cert) - dt.timedelta(days=RENEW_BEFORE_DAYS):
        log.warning("Certificate %s expires on %s; renew it.", cert_path, f"{_expires(cert):%F}")


# ---------------------------------------------------------------- public API
def _host_names(hosts: Iterable[str]) -> tuple[list[str], list[str]]:
    """Split user-supplied hosts (e.g. the --host bind address) into DNS names and IPs.

    Wildcard binds (0.0.0.0, ::, empty) say nothing about what clients will type, and
    anything that is neither an IP nor a plausible host name is ignored.
    """
    dns, ips = [], []
    for raw in hosts:
        host = (raw or "").strip().strip("[]")
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            if _HOSTNAME_RE.match(host):
                dns.append(host.lower())
            continue
        if not (ip.is_unspecified or ip.is_multicast or ip.is_link_local):
            ips.append(str(ip))
    return dns, ips


def ensure_cert(
    directory: Path,
    *,
    extra_hosts: Iterable[str] = (),
    now: dt.datetime | None = None,
    dns_names: list[str] | None = None,
    ip_addresses: list[str] | None = None,
) -> TlsFiles:
    """Return the TLS certificate, key and fingerprint to serve with, creating them if needed.

    ``extra_hosts`` are additional names or addresses clients will use (such as the bind
    address); they are added to the certificate. Raises :class:`TlsError` if existing files
    cannot be used. Files PPS did not generate are never overwritten.
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    directory = Path(directory)
    try:  # no exists() check first: two processes starting together would race on it
        directory.mkdir(parents=True)
    except FileExistsError:
        pass  # someone else's directory (or a racing process): leave its permissions alone
    else:
        try:
            directory.chmod(0o700)
        except OSError:
            pass
    cert_path, key_path = directory / CERT_NAME, directory / KEY_NAME
    if dns_names is None or ip_addresses is None:
        auto_dns, auto_ips = local_names()
        dns_names = auto_dns if dns_names is None else dns_names
        ip_addresses = auto_ips if ip_addresses is None else ip_addresses
    extra_dns, extra_ips = _host_names(extra_hosts)
    dns_names = sorted(set(dns_names) | set(extra_dns))
    ip_addresses = sorted(set(ip_addresses) | set(extra_ips))

    have_cert, have_key = cert_path.exists(), key_path.exists()
    reason = "no certificate yet"
    if have_cert and have_key:
        cert, key = _load_pair(cert_path, key_path)
        if not _is_ours(cert):
            _check_supplied(cert, key, now, cert_path)
            return TlsFiles(cert_path, key_path, fingerprint(cert))
        reason = (
            "private key unreadable"
            if key is None
            else _needs_regeneration(cert, key, dns_names, ip_addresses, now)
        )
        if reason is None:
            return TlsFiles(cert_path, key_path, fingerprint(cert))
    elif have_key:
        raise TlsError(
            f"{key_path} exists without {cert_path}. Add the matching certificate, "
            "or delete the key to have PPS generate a new pair."
        )
    elif have_cert:
        try:
            lone = x509.load_pem_x509_certificate(cert_path.read_bytes())
        except (ValueError, OSError) as exc:
            raise TlsError(
                f"Cannot read certificate {cert_path}: {exc}. "
                "PPS will not overwrite it; fix or delete it."
            ) from None
        if not _is_ours(lone):
            raise TlsError(
                f"{cert_path} exists without {key_path}. Add its private key, "
                "or delete the certificate to have PPS generate a new pair."
            )
        reason = "incomplete pair left by an interrupted run"

    log.info("Generating a self-signed TLS certificate (%s)", reason)
    cert_pem, key_pem = generate_self_signed(dns_names, ip_addresses, now=now)
    _write_atomic(cert_path, cert_pem, 0o644)
    _write_atomic(key_path, key_pem, 0o600)
    return TlsFiles(cert_path, key_path, fingerprint(x509.load_pem_x509_certificate(cert_pem)))


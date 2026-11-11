# Pocket Packet Sniffer (PPS)

A portable network packet capture and analysis tool: capture on a Wi-Fi
interface, decode common protocols, store captures as PCAP, detect basic
anomalies (ARP spoofing, port scans, rogue APs) and control it from a
companion web app. See [`Pocket_Packet_Sniffer_SRS.md`](Pocket_Packet_Sniffer_SRS.md)
for the requirements.

> **Status:** early development. Only the repository scaffolding and the
> configuration module (`pps/settings.py`) exist so far. Capture, decoding,
> storage, alerting and the API arrive in later pull requests.

Capture only on networks you own or are explicitly authorised to monitor.

## Development setup

Requires Python 3.10 or newer.

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements-dev.txt
pip install -e .
```

## Checks

```bash
ruff check .
python -m pytest -q
```

## Configuration

`pps.settings.Settings.from_env()` reads `PPS_*` environment variables and
validates them at start-up.

| Variable | Default | Meaning |
|---|---|---|
| `PPS_INTERFACE` | unset | Capture interface name |
| `PPS_CAPTURE_DURATION_S` | unlimited | Stop capture after N seconds |
| `PPS_CAPTURE_PACKET_LIMIT` | unlimited | Stop capture after N packets |
| `PPS_DATA_DIR` | `data` | Where captures and the database live |
| `PPS_API_HOST` | `127.0.0.1` | API bind address |
| `PPS_API_PORT` | `8443` | API port |
| `PPS_TLS_ENABLED` | `true` | Serve the API over TLS |
| `PPS_PORT_SCAN_THRESHOLD` | `20` | Distinct ports within the window that count as a scan |
| `PPS_PORT_SCAN_WINDOW_S` | `10` | Port-scan detection window (seconds) |
| `PPS_STORAGE_WARN_PERCENT` | `80` | Storage usage that triggers a warning |

## Capture interfaces

`pps.interfaces` lists and selects the interface to capture on (PPS-F-001):

```bash
python -m pps.interfaces      # list interfaces, the modes each supports, and permission status
```

- **Promiscuous mode** works on any interface, but on Wi-Fi only shows the network the adapter is associated with.
- **Monitor mode** is wireless-only and delivers raw 802.11 frames. It needs driver support, and is detected on Linux via sysfs and `iw`. Where that can't be determined (no `iw`, non-Linux) monitor mode is reported as unavailable rather than guessed.
- Capturing needs root or `CAP_NET_RAW` (plus `CAP_NET_ADMIN` to switch modes). The module returns the exact `setcap` command when a capability is missing.
- `set_monitor_mode()` is Linux-only and uses `ip` and `iw`; a network manager (e.g. NetworkManager) may reclaim the adapter afterwards.

## Authentication and roles

`pps.auth.AuthService` provides accounts, roles and tokens (PPS-SR-004, PPS-F-061):

- **Roles:** `trainee` < `analyst` < `admin`. `require_role(principal, Role.X)` enforces a minimum; all user-management methods require `admin` themselves.
- **Pairing:** a client exchanges the device PIN for a client token; login needs that token plus a username and password and returns a short-lived access token (`token_ttl_s`, default 1 hour).
- **Passwords:** scrypt with a per-password salt; 8-128 characters. On first run `bootstrap_admin()` creates `admin` with a random password, shown once.
- **Lockout:** after `pairing_lockout_attempts` failures (default 5) pairing is locked device-wide, and login is locked per username, for `pairing_lockout_s` seconds (default 300).
- **Safeguards:** the last active administrator cannot be demoted or disabled; disabling a user or changing a password revokes their sessions; role changes apply to existing tokens immediately.
- **Audit:** logins, pairing, lockouts and user changes are written to the audit log; passwords, PINs and tokens never are.

Tokens and lockout state are held in memory, so restarting the service signs everyone out and clears lockouts.

## HTTPS

`python -m pps` serves the dashboard and API over HTTPS (PPS-SR-002) using `pps/tlsutil.py`. On first run it creates a **self-signed certificate for local demonstration** in `<data dir>/tls/` (`cert.pem`, `key.pem`; the key is mode 0600).

- **Expect a browser warning once.** No authority vouches for a self-signed certificate. Compare the SHA-256 fingerprint printed in the start-up banner with the one the browser shows before choosing *Advanced → Proceed*, or import the certificate as trusted. This encrypts traffic, but does not prove the device's identity to someone who is not checking the fingerprint.
- **The certificate follows the device.** It covers `localhost`, the loopback addresses, the host name (and `<host>.local`), the primary LAN address, the addresses of up Wi-Fi interfaces, and the `--host` you bind to. It is valid for one year and re-issued automatically when close to expiry or when those names change (the fingerprint then changes too).
- **For anything beyond a demo, bring your own certificate.** Put one issued by a real or private CA in `<data dir>/tls/cert.pem` with its unencrypted key in `key.pem`. Files PPS did not generate are used as they are, never overwritten, and an expired or mismatched pair stops start-up with a clear message.
- `--no-tls` (or `PPS_TLS_ENABLED=false`) serves plain HTTP for development only; PINs, passwords and tokens then cross the network unencrypted, and the banner says so.
- The minimum TLS version comes from the platform's OpenSSL defaults; PPS does not set its own floor.

## Workflow

Work lands through pull requests reviewed by the repository owner; see the
planned PR sequence in the project guide.

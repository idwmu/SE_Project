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

## Workflow

Work lands through pull requests reviewed by the repository owner; see the
planned PR sequence in the project guide.

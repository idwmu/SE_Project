# Demo script

Run the demo from a clean clone, then record the screen (OBS, Xbox Game Bar with Win+Alt+R, or Loom). Start the server first and pair and sign in before recording, so the video shows only the product. Keep each video under about 25 MB, because GitHub rejects files over 100 MB.

## Setup

```bash
python -m pip install -r requirements-dev.txt && python -m pip install -e .
python tools/make_demo_pcaps.py data/replay     # writes normal_traffic, arp_spoof, port_scan, demo_all
python -m pps                                   # https://localhost:8443
```

The start-up banner prints the pairing PIN, the TLS certificate fingerprint and, on the first run only, the admin password. The browser warns about the self-signed certificate; compare its fingerprint with the banner before continuing.

Live capture needs Npcap on Windows, or `CAP_NET_RAW` on Linux. Replay works without either.

## What the smoke test checked

Before this script was written, the demo path was run on a local server:

- A wrong PIN was refused with 401. The right PIN paired, and admin login succeeded.
- Replaying `demo_all.pcap` at full speed finished with status DONE and 631 packets stored.
- The alerts were `ARP_SPOOF` and `PORT_SCAN`.

Steps marked **(manual)** below were not run automatically: they need a browser or a live adapter.

## Sprint 1 (1 minute): capture, decode, live view, PCAP saved

| Time | Show | Say |
|---|---|---|
| 0:00 | Terminal with the `python -m pps` banner | "Pocket Packet Sniffer, Sprint 1. The backend runs over HTTPS and asks for a pairing PIN." |
| 0:08 | Live capture tab, Replay PCAP, `normal_traffic.pcap`, 1x, Start (manual) | "We start a capture from a recorded file, so the demo is repeatable." |
| 0:15 | Status ACTIVE, packets streaming, stats cards (manual) | "Packets stream to the browser over a WebSocket; the counters update." |
| 0:25 | Click an HTTP packet, then a DNS packet (manual) | "Each packet is decoded layer by layer. DNS and HTTP are labelled." |
| 0:38 | Live tab, pick the Wi-Fi adapter, tick the authorisation box, Start, stop after a few seconds (manual, needs Npcap or `CAP_NET_RAW`) | "The same pipeline works on live traffic from this laptop's adapter, once the user confirms they are allowed to capture." |
| 0:50 | Status IDLE; Sessions tab showing the saved PCAP; GitHub Actions green on the repository | "The session is saved as a PCAP file. CI runs lint, tests and the module-boundary check on every pull request." |

## Sprint 2 (2 minutes): filters, storage, alerts, security, management

| Time | Show | Say |
|---|---|---|
| 0:00 | Pair screen: wrong PIN, then the right PIN, sign in (manual) | "Browsers pair with the device PIN. Wrong PINs are refused, and five failures lock pairing for five minutes." |
| 0:12 | Replay `demo_all.pcap` at 4x | "This lab capture contains normal traffic, a port scan and an ARP spoofing attack." |
| 0:20 | Type `dns or http` in the filter box; save it as a preset (manual) | "Display filters combine with and, or and not, and can be saved as presets." |
| 0:35 | Port-scan and ARP-spoof alerts appear (manual) | "The detectors raise a port-scan alert and an ARP-spoofing alert, with the MAC change." |
| 0:50 | Alerts tab; acknowledge one as an analyst (manual) | "Alerts are stored with timestamps, and an analyst can acknowledge them." |
| 1:00 | Sessions tab: open the session, filter `arp and eth.src == 02:50:00:00:00:66`, download the PCAP, open it in Wireshark (manual) | "Stored sessions can be searched and exported as standard PCAP files." |
| 1:20 | Device health tab (manual) | "The health view shows battery where the device has one, storage use, uptime, CPU and memory." |
| 1:30 | Admin tab: create a trainee; sign in as the trainee in a private window; Start is disabled and the Admin tab is missing (manual) | "Role-based access: trainees can watch, but cannot capture or change settings." |
| 1:45 | Settings tab: change the port-scan threshold; Admin tab shows "Hash chain verified" (manual) | "Security-relevant actions go into a hash-chained audit log, and the device checks the chain." |
| 1:55 | Terminal: `python -m pytest -q` | "372 automated tests back this up, run on Python 3.10 and 3.12 in CI." |

## Caveats to say out loud

- The certificate is self-signed for this demo. Trust depends on comparing the fingerprint, not on a certificate authority.
- The Windows development run had test failures in interface and TLS tests (see `docs/DEVIATIONS.md`, D16). CI on Linux passes.
- The performance numbers come from replayed traffic, not a live adapter (D17).

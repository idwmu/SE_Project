# Deviations from SRS v1.0, SAD and Test Plan v1.0

Each entry gives what was specified, what was built, why, and the effect on requirements and tests.
Every "built" statement was checked against the code on `main` when this file was written.

**Note on the SAD and Test Plan.** The SRS is in the repository. The SAD is not in the repository, so the SAD column below cites section numbers from the team's design notes and has not been checked against the submitted SAD. Test Plan v1.0 was committed to the repository (commit `97fb8a4`) and then removed (commit `21c0791`). Its test-case IDs (TC-...) are used here as the reference.

## Platform and hardware

| # | Specified | Built | Reason | Impact |
|---|---|---|---|---|
| D1 | 802.11 monitor mode on an external USB adapter (PPS-F-001) | Capture is promiscuous (Scapy/libpcap) plus PCAP replay. On Linux, `pps.interfaces` detects monitor-capable adapters through sysfs and `iw`, and `set_monitor_mode()` can switch one. The capture engine does not switch modes. | Npcap on Windows and most laptop Wi-Fi drivers do not support monitor mode. | On Windows and most laptops, live capture sees only traffic addressed to the machine plus broadcast traffic on the associated network. Monitor-mode switching has only been tested against fake `ip`/`iw` commands, not a real adapter. |
| D2 | Rogue access point detection (PPS-F-042) | Not implemented | Needs 802.11 beacon frames from a monitor-mode adapter (D1). The decoder parses beacons when they are present, but no detector uses them. | TC-Anom-03 not run. |

## Software design

| # | Specified | Built | Reason | Impact |
|---|---|---|---|---|
| D3 | libpcap via pcapy-ng and dpkt decoding, capture in a separate process (SAD ADR-03) | Scapy for capture and decoding, with capture running in a thread inside the server process | Scapy works the same on Windows (with Npcap) and Linux, and decodes every required protocol | Throughput results come from one machine (see D13). |
| D4 | Encryption at rest with AES-256-GCM, key from an admin passphrase (PPS-SR-003) | Not implemented. Captures are plain PCAP files in the data folder. | Time. Lower risk on a personal laptop than on a removable microSD. | PPS-SR-003 not met. TC-Sec-03 not run. This is the first item to build next. |
| D5 | Argon2id password hashing (SAD 3.4) | scrypt from the Python standard library, with a per-password salt | Avoids a native dependency that is awkward on Windows | Same purpose: a memory-hard password hash. |
| D6 | 15-minute access token and a refresh token (SAD 4.3) | 1-hour access token. There is no refresh token or refresh endpoint. | Simpler for the demo | Users sign in again after an hour. Tokens and lockout state are held in memory, so a server restart signs everyone out. |
| D7 | `/pair` returns a `client_id` and `client_secret` (SAD 4.3) | `/pair` returns one opaque random token, which the browser sends as the `x-pps-client` header. The server stores only a SHA-256 digest of it and expires it after 30 days. | One token is simpler and can be revoked by its digest | Pairing is still required before login (PPS-SR-001). The token is not a signed JWT. |
| D8 | Capture (BPF) filters (PPS-F-020) | BPF applies to live capture only. Replay rejects a BPF filter with `BPF_LIVE_ONLY`, and replay uses display filters instead. | BPF on a file needs tcpdump, which Windows lacks | The same searches are possible on replays with display filters, such as `dns or http`. |
| D9 | Archival of old sessions (PPS-F-033) | Not implemented. Rotation (PPS-F-032) deletes the oldest finished sessions over the quota, and deletes nothing if that cannot bring usage under the quota. | Time | PPS-F-033 not met. TC-Sto-04 not run. |
| D10 | Roles "Administrator" and "standard user" (PPS-SR-004) | Three roles: admin, analyst and trainee. Trainees are read-only. | SRS 2.3 also defines a Student/Trainee user | More granular than specified. PPS-SR-004 is met by the admin-only restrictions. |
| D11 | Tamper-evident audit log (PPS-SR-005) | SHA-256 hash chain in SQLite. `Storage` supports an HMAC key and checking against an externally stored head hash, but the application does not configure either. | Key storage belongs with encryption at rest (D4) | Edits and deletions in the middle of the log are detected, and the admin tab shows the result. Removing only the newest entries is not detected, and anyone with write access to the database can rebuild the chain. |

## Found while verifying (added for this release)

| # | Specified | Built | Reason | Impact |
|---|---|---|---|---|
| D12 | Tests run on the development platform | CI runs the full suite on Linux (Python 3.10 and 3.12) and passes. The development test run on Windows recorded 360 passed, 3 skipped, 7 errors and 2 failures. The 7 errors are interface tests that create symbolic links, which Windows forbids without privileges. The 2 failures are concurrent certificate creation in the TLS tests. | Windows restricts symbolic links, and the concurrency test depends on file-replacement timing | Those tests do not run cleanly on Windows. The results are documented in `docs/TEST_REPORT.md`. |
| D13 | Latency and packet-loss targets on live traffic (PPS-NF-001, PPS-NF-003) | Measured with replayed PCAPs at 100, 500 and 1000 packets per second on one machine, through the same pipeline and WebSocket | A live NIC and driver were not part of the benchmark | Results do not include the NIC or driver. Latency includes the 250 ms WebSocket batching interval. |
| D14 | Test Plan TC-Cap-01 (interface listing and live capture) | Interfaces are listed. Live capture was checked by hand on loopback, not in an automated test. | Live capture needs Npcap or root privileges | TC-Cap-01 is "Manual" in the test report. |
| D15 | CA-issued certificate for the control API (PPS-SR-002) | Self-signed certificate generated on first run, with an automatic renewal before expiry. A CA-issued certificate can be placed in the data folder, but this path was not tested. | No certificate authority is available for a demo | The browser warns once. Trust depends on comparing the fingerprint printed at start-up. |
| D16 | Schedule: Sprint 1 (19 to 23 October) and Sprint 2 (26 to 30 October) | Stages were merged between 29 October and 16 November. PR 23 (this document) is the last stage. | Stages were built late, and some reviews and fixes took several days | Late delivery, recorded here rather than changed in history. See `docs/PR_PLAN.md`. |

## Values the SRS left open (decided here)

- Throughput for PPS-NF-003: 1000 packets per second, the same load as PPS-NF-001.
- Port-scan threshold: 20 distinct destination ports from one source to one host within 10 seconds (`PPS_PORT_SCAN_THRESHOLD`, `PPS_PORT_SCAN_WINDOW_S`, also editable on the Settings page).
- Low-storage warning: at 80% of the quota used (`PPS_STORAGE_WARN_PERCENT`).
- ARP spoofing: an alert when an IP's MAC address changes to one that is not whitelisted. Repeats are suppressed for 60 seconds.
- Live-view latency: measured from a packet entering the pipeline to delivery to the WebSocket. Browser rendering is excluded.

## Tests from the Test Plan not run

TC-Power-01 (battery-powered hardware, deferred in the SRS), TC-Anom-03 (D2), TC-Sec-03 (D4), TC-Sto-04 (D9), TC-UX-01 (no user study yet), and TC-Rob-02 (schemathesis not run). See `docs/TEST_REPORT.md` for everything that was run.

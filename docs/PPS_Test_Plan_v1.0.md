# Software Test Plan (STP) - Pocket Packet Sniffer (PPS)
Project: Pocket Packet Sniffer (PPS)
Version: 1.0
Date: 22-10-2026
Status: Draft v1.0

### 1. Introduction
Purpose: This document defines the test plan for the Pocket Packet Sniffer (PPS) v1.0. It sets out objectives, scope, strategy, environment, schedule, responsibilities and traceability for verifying the requirements in PPS SRS v1.0 against the design in PPS SAD v1.0.
Scope: Testing covers the on-device software (capture, decoding, filtering, storage, anomaly detection, control API, pairing, authentication, device management), the companion app (Android build), and the hardware integration needed for the performance, power and portability requirements. Excluded: payload decryption and intrusion prevention (out of scope in SRS 1.2), capture on any network the team does not own, and hardware durability. All capture tests run on the team's isolated lab network.
References: PPS SRS v1.0 (08-09-2026); PPS SAD v1.0 (22-10-2026); ISO/IEC/IEEE 29119-3 (test documentation); libpcap / PCAP file format documentation; IEEE 802.11-2020.
Definitions: DUT (Device Under Test), Lab AP (team-owned access point with no uplink), Golden PCAP (reference capture whose decoded fields are verified with Wireshark / tshark), Reference sniffer (laptop with a second monitor-mode adapter running Wireshark), p90 (90th percentile), RTM (Requirements Traceability Matrix), UAT (User Acceptance Testing). Other acronyms as in SRS 1.4.

### 2. Test Items
- CaptureModule (monitor mode, start/stop, limits)
- DecodeModule (radiotap, 802.11, Ethernet, ARP, IPv4/IPv6, TCP, UDP, ICMP, DNS / HTTP labelling)
- FilterModule (BPF capture filters, display filters, presets)
- StorageModule (PCAP files, rotation / archival, SQLite, encryption at rest)
- AlertModule (ARP spoofing, port scan, rogue AP detectors; alert delivery)
- APIModule (REST + WebSocket over TLS) and AuthModule (accounts, RBAC, audit log)
- PairingService (BLE PIN / QR pairing)
- DeviceManager (health view, OLED, LEDs, buttons, low-battery shutdown)
- Companion App (Flutter, Android build; iOS smoke test only)
- Integrated device: Raspberry Pi Zero 2 W + MT7612U adapter + PiSugar 3 Plus battery (for NF tests)
Builds under test are tagged v1.0-rcN in the team repository and flashed as a full SD image.

### 3. Features to be Tested
Features mapped to SRS requirement IDs:

| Req ID | Feature | Priority |
|---|---|---|
| PPS-F-001 | Select interface and switch to monitor mode | High |
| PPS-F-002 | Start / stop capture on demand or at duration / packet limit | High |
| PPS-F-003 | Capture-status indicator on device and app | Medium |
| PPS-F-010 | Decode Ethernet, IPv4/IPv6, TCP, UDP, ICMP, ARP (and 802.11 / radiotap, per SAD ADR-07) | High |
| PPS-F-011 | Label DNS and HTTP | Medium |
| PPS-F-020 * | BPF capture filters | High |
| PPS-F-021 * | Display filters / search by IP, port, protocol, MAC | High |
| PPS-F-022 * | Combinable filters (AND / OR / NOT) | Medium |
| PPS-F-023 * | Saveable filter presets | Low |
| PPS-F-030 * | Persist captures as PCAP | High |
| PPS-F-031 * | Export / download via companion app | High |
| PPS-F-032 * | Rotation of old sessions when space is low | Medium |
| PPS-F-033 * | Archival of older sessions | Low |
| PPS-F-034 * | Low-storage warning threshold | Medium |
| PPS-F-040 * | Detect ARP spoofing | High |
| PPS-F-041 * | Detect port scans | High |
| PPS-F-042 * | Detect rogue access points | Medium |
| PPS-F-043 * | Timestamped alert pushed to companion app | High |
| PPS-F-050 * | Pair app over Wi-Fi / BLE with PIN or QR | High |
| PPS-F-051 * | Stream live capture summaries to app | High |
| PPS-F-052 * | Remote start / stop / configuration from app | High |
| PPS-F-060 * | Configure interface, duration / limits, alert thresholds | Medium |
| PPS-F-061 * | Manage user accounts | Medium |
| PPS-F-062 * | Device health view (battery, storage, uptime) | Medium |
| PPS-NF-001 | Live-view latency p90 of 1 s or less at up to 1000 pkt/s | High |
| PPS-NF-002 | At least 4 h capture on a full charge | High |
| PPS-NF-003 | Packet loss of 1% or less at rated throughput | High |
| PPS-NF-004 | At least 80% of first-time users complete a guided task | Medium |
| PPS-NF-005 | Runs unmodified on two Linux SBC targets | Medium |
| PPS-NF-006 | Modular codebase | Medium |
| PPS-SR-001 to SR-005 | Authenticated pairing, encrypted API, encryption at rest, RBAC, audit log | High / Medium (per SRS 5.1.2) |

* SRS 4.3 to 4.7 give only ID ranges. The per-ID split above is the team's working assumption (also used in SAD 3.8) and will be updated when SRS v1.1 defines these rows. Priorities for these IDs are proposed.

### 4. Features Not to be Tested
- Decryption of encrypted payloads and active intrusion prevention (out of scope, SRS 1.2)
- Capture on networks not owned by the team (legal / ethical constraint, SRS 2.5)
- Session summary report and firmware update (listed in SRS 2.2 / use-case diagram but have no requirement IDs in SRS v1.0; added if SRS v1.1 defines them)
- Internals of libpcap, the Linux kernel and the mt76 driver (third-party; exercised only through PPS functions)
- iOS build beyond a smoke test (Android is the primary platform, SAD ADR-04)
- Hardware durability: drop, thermal and water resistance

### 5. Test Approach / Strategy
Levels:
- Unit tests (pytest, per module): decoders against golden PCAPs; detectors with synthetic frame sequences built with Scapy; filter expressions; storage rotation logic. Target 80% line coverage for Decode, Filter and Alert modules.
- Integration tests: capture, decode, event bus, alert, storage and API on the DUT, fed by tcpreplay in the lab; API contract tests against the generated OpenAPI schema.
- System tests: end-to-end with the Android app on the lab network, including all NF and security tests.
- Acceptance tests: SRS Section 6 exit criteria demonstrated to the Project Guide; usability sessions with first-time users.
Types:
- Functional testing (all PPS-F requirements)
- Regression testing (automated unit + API suite on every merge to main and before each release candidate)
- Performance testing (latency, throughput, packet loss)
- Reliability / power testing (4 h battery soak)
- Usability testing (first-time users, guided task)
- Portability testing (second SBC target)
- Security and robustness testing (Section 5.1)
Defect severity: Critical (crash, data loss, security bypass); High (requirement fails with no workaround); Medium (fails with workaround); Low (cosmetic).
Entry Criteria: tagged build flashed to the DUT; smoke test passes (boot, hotspot up, wlan1 enters monitor mode, app pairs); lab AP, golden PCAPs and test accounts ready; test cases reviewed.
Exit Criteria: 100% of planned test cases executed; all High priority requirements pass; 0 open Critical or High defects; PPS-NF-001, NF-002 and NF-003 measured and meeting targets (or a waiver signed by the Project Guide); RTM updated with results (SRS Section 6).

### 5.1 Security Validation
- Pairing: wrong PIN, expired or replayed QR token, and brute force all refused; lockout after 5 failures (TC-Sec-01).
- Transport: capture app-to-device traffic on the hotspot with the reference sniffer; confirm TLS 1.3 and no plaintext JSON; present a mitmproxy certificate and confirm the app rejects it (TC-Sec-02).
- At rest: remove the microSD, mount it on a laptop, attempt to read PCAPs, the SQLite database and credentials (TC-Sec-03).
- RBAC: call every Admin endpoint with Analyst and Trainee tokens (expect 403); tampered JWTs (changed role, alg "none") rejected (TC-Sec-04).
- Audit log: entries for each event type; edit one stored entry and confirm chain verification fails (TC-Sec-05).
- Logs: search journald output after a full test cycle for PINs, passwords, tokens and payload bytes (expect none).
- Exposure: nmap scan of the device from the hotspot shows only the API port and hotspot services (DHCP, DNS, mDNS).
- Fuzzing: malformed and truncated frames into the decoder (TC-Rob-01); schema-based API fuzzing (TC-Rob-02).

### 6. Test Environment
Hardware: 2 PPS units (Raspberry Pi Zero 2 W, MT7612U USB adapter, PiSugar 3 Plus 5000 mAh, SSD1306 OLED); secondary SBC for PPS-NF-005 (Raspberry Pi 4 Model B or Orange Pi Zero 3); isolated lab AP with no uplink, configured with an open SSID "PPS-LAB-OPEN" and a WPA2 SSID "PPS-LAB-WPA2" on a fixed channel; laptop 1 (traffic generator / attacker); laptop 2 (reference sniffer with its own monitor-mode adapter); 2 Android phones (Android 12+); 1 iPhone (smoke only); USB power meter.
Software: PPS image v1.0-rcN; companion app APK; Wireshark / tshark 4.x; tcpreplay; Scapy; nmap; hostapd (rogue AP); mitmproxy; pytest, httpx, schemathesis; import-linter; chrony on all hosts (clock sync for latency); GitHub Issues (defect tracking).
Test Data: golden PCAPs (Wireshark sample captures plus team lab captures, decoded fields verified with tshark); a labelled set of at least 1000 DNS / HTTP packets including non-standard ports; traffic profiles at 100, 200, 500, 1000 and 1500 pkt/s; test accounts (admin1, analyst1, trainee1); BSSID allow-list for the lab AP.
Lab rule: captures are restricted to the lab BSSID with a BPF filter; any frames from other networks are deleted at the end of each session.

### 7. Test Schedule
Milestones (tentative; to be aligned with course deadlines):
- Test case design and review: 26-Oct-2026 to 30-Oct-2026
- Environment setup (lab AP, golden PCAPs, DUT image): 02-Nov-2026 to 04-Nov-2026
- Early performance benchmark (NF-001 / NF-003 spike): 05-Nov-2026
- Execution cycle 1 (unit + integration): 05-Nov-2026 to 13-Nov-2026
- Execution cycle 2 (system, security, NF): 16-Nov-2026 to 24-Nov-2026
- Regression + UAT / usability sessions: 25-Nov-2026 to 28-Nov-2026
- Test Summary Report: 30-Nov-2026

### 8. Test Deliverables
- Test Plan (this document)
- Test case specification (catalogue in Section 13)
- Automated test suites (tests/ in the repository)
- Test data (golden PCAPs, traffic profiles, labelled DNS / HTTP set)
- Execution logs and raw measurements (latency CSVs, loss counts, battery logs)
- Defect reports (GitHub Issues)
- Updated RTM and Test Summary Report

### 9. Roles and Responsibilities

| Role | Name | Responsibility |
|---|---|---|
| QA Lead | <Name> | Prepare plan, coordinate execution, maintain RTM |
| Test Engineer | <Name> | Design and execute test cases, log defects, run NF benchmarks |
| Developer | <Name> | Unit tests, defect fixes and triage |
| Project Guide (Product Owner) | <Name> | Approve test results and waivers, sign off acceptance |


### 10. Risks and Mitigation

| Risk | Mitigation |
|---|---|
| Python pipeline misses NF-001 / NF-003 targets | Benchmark on 05-Nov before full execution; C fallback per SAD 3.7 |
| Monitor-mode adapter or driver fails on the DUT | Validate during setup; keep a spare adapter with a different chipset |
| Encrypted traffic prevents IP-layer tests | Run L3+ decode and detector tests on the open lab SSID (SAD ADR-07) |
| RF interference distorts loss measurements | Fixed channel, off-peak hours, compare against the reference sniffer rather than only the sender count |
| Too few usability participants | Recruit 5 to 10 classmates outside the team early |
| Battery capacity below rating | Measure capacity before TC-Power-01; keep a second battery |
| Accidental capture of third-party traffic | BSSID BPF filter, isolated AP, end-of-session deletion (Section 6) |


### 11. Assumptions & Dependencies
- SRS v1.1 will confirm the per-ID breakdown of PPS-F-020 to F-062 used in Section 3.
- "Rated maximum throughput" in PPS-NF-003 is taken as 1000 pkt/s (same load as NF-001) until the SRS gives a value.
- Hardware is available by 02-Nov-2026.
- The Project Guide approves running ARP spoofing, port scans and a rogue AP inside the isolated lab.
- Wireshark / tshark output is the ground truth for decoding and packet counts.
- All hosts are time-synchronised with chrony for latency measurement.

### 12. Suspension & Resumption Criteria
Suspend testing if:
- The DUT cannot boot or enter monitor mode (blocks more than 30% of test cases)
- The build blocks more than 30% of test cases for any other reason
- The lab AP or reference sniffer is unavailable for more than 1 working day
- Traffic from a network outside the lab is found in a capture (ethics stop)
Resume testing if:
- Blocking defects are fixed and the smoke test passes
- The environment is restored and re-validated
- For an ethics stop: the cause is fixed, the data deleted, and the Project Guide informed

### 13. Test Case Management & Traceability
Test cases are named TC-<Area>-NN and kept in the repository alongside the automated suites. Each result records build tag, date, tester, result (Pass / Fail / Blocked / Not run) and linked defects. The RTM below extends SRS Section 8 to every requirement.
Changes from SRS RTM: PPS-F-040 now maps to TC-Anom-01 (was "TC-Sec-anomaly", renamed to follow the TC-<Area>-NN pattern). PPS-F-050 maps to TC-App-01 for function and TC-Sec-01 for security.
Requirements Traceability Matrix

| Req ID | Test case(s) | Level | Type |
|---|---|---|---|
| PPS-F-001 | TC-Cap-01 | System | Functional |
| PPS-F-002 | TC-Cap-02 | Integration, System | Functional |
| PPS-F-003 | TC-Cap-03 | System | Functional |
| PPS-F-010 | TC-Dec-01, TC-Rob-01 | Unit | Functional, Robustness |
| PPS-F-011 | TC-Dec-02 | Unit | Functional |
| PPS-F-020 .. F-023 | TC-Filt-01 .. TC-Filt-04 | Unit, Integration | Functional |
| PPS-F-030 .. F-034 | TC-Sto-01 .. TC-Sto-05 | Integration, System | Functional |
| PPS-F-040 .. F-042 | TC-Anom-01 .. TC-Anom-03 | System | Functional |
| PPS-F-043 | TC-Anom-04 | System | Functional |
| PPS-F-050 | TC-App-01, TC-Sec-01 | System | Functional, Security |
| PPS-F-051, F-052 | TC-App-02, TC-App-03 | System | Functional |
| PPS-F-060 .. F-062 | TC-Cfg-01 .. TC-Cfg-03 | System | Functional |
| PPS-NF-001 | TC-Perf-01 | System | Performance |
| PPS-NF-002 | TC-Power-01 | System | Reliability / Power |
| PPS-NF-003 | TC-Rel-01 | System | Performance |
| PPS-NF-004 | TC-UX-01 | Acceptance | Usability |
| PPS-NF-005 | TC-Port-01 | System | Portability |
| PPS-NF-006 | TC-Maint-01 | Code review | Maintainability |
| PPS-SR-001 | TC-Sec-01 | System | Security |
| PPS-SR-002 | TC-Sec-02 | System | Security |
| PPS-SR-003 | TC-Sec-03 | System | Security |
| PPS-SR-004 | TC-Sec-04, TC-Rob-02 | Integration | Security |
| PPS-SR-005 | TC-Sec-05 | Integration | Security |

Test Case Catalogue

| TC ID | Req | Procedure (summary) | Pass criterion |
|---|---|---|---|
| TC-Cap-01 | F-001 | Select wlan1 in the app and enable monitor mode. Repeat with an interface that does not support monitor mode. | "iw dev" shows type monitor, no error. Unsupported interface returns 503 MONITOR_MODE_FAILED with a clear message. |
| TC-Cap-02 | F-002 | Start and stop 10 times via the API, timing each acknowledgement; run with a 60 s duration limit and a 1000-packet limit. | Every start / stop acknowledged within 2 s. Duration session ends at 60 s (+/- 1 s); packet-limit session holds exactly 1000 packets. |
| TC-Cap-03 | F-003 | Start / stop from app and from button B; film OLED, LED and app at 60 fps. | All indicators show the true state within 1 s. |
| TC-Dec-01 | F-010 | Decode golden PCAPs covering radiotap, 802.11, Ethernet, ARP, IPv4, IPv6, TCP, UDP, ICMP; compare every field with tshark -T json. | 100% field match on the golden set. |
| TC-Dec-02 | F-011 | Classify the labelled DNS / HTTP set (at least 1000 packets, including non-standard ports). | At least 95% labelled correctly. |
| TC-Filt-01 | F-020 | Capture with BPF "tcp port 80 and host 192.168.50.20"; submit an invalid BPF. | Saved PCAP holds only matching packets (verified with tshark). Invalid BPF returns 400 BPF_INVALID. |
| TC-Filt-02 | F-021 | Apply display filters by IP, port, protocol and MAC on a stored session. | Result sets equal the equivalent tshark display filters. |
| TC-Filt-03 | F-022 | Combine filters with AND / OR / NOT (10 expressions). | Result sets equal tshark for all 10. |
| TC-Filt-04 | F-023 | Save, reboot, reload, edit and delete presets. | Presets persist across reboot; edits and deletes take effect. |
| TC-Sto-01 | F-030 | Run a 10 min capture and export it. | File opens in Wireshark without errors; packet count equals the session summary. |
| TC-Sto-02 | F-031 | Download a session from the app; compare SHA-256 with the device-side plaintext export. | Hashes match; file opens in Wireshark. |
| TC-Sto-03 | F-032 | Fill storage below the threshold with old sessions, then capture. | Oldest sessions rotated first; active session unaffected. |
| TC-Sto-04 | F-033 | Trigger archival of sessions older than the configured age. | Archived sessions listed and still exportable. |
| TC-Sto-05 | F-034 | Reduce free space past the warning threshold (default 15%). | Warning shown in app and on OLED within 10 s. |
| TC-Anom-01 | F-040 | From laptop 1, send forged ARP replies for the lab gateway (10 runs); run 30 min of benign traffic. | Alert in 10 / 10 runs with correct IP and both MACs; 0 false positives in the benign run. |
| TC-Anom-02 | F-041 | nmap -sS and -sT scans of a lab host (10 runs); 30 min benign browsing. | Alert in 10 / 10 runs; 0 false positives in the benign run. |
| TC-Anom-03 | F-042 | Start a hostapd AP with the lab SSID and a non-whitelisted BSSID. | Rogue AP alert with BSSID and channel. |
| TC-Anom-04 | F-043 | For alerts from TC-Anom-01 to 03, check storage, timestamps and app delivery with the app in foreground and background (Android). | Every alert stored with a UTC timestamp and shown in the app within 2 s of being raised. |
| TC-App-01 | F-050 | Pair via QR and via PIN; drop the hotspot for 20 s. | Pairing succeeds both ways; app reconnects with backoff and resumes the stream. |
| TC-App-02 | F-051 | Stream a 1000 pkt/s session for 5 min. | App counters within 1% of device counters. |
| TC-App-03 | F-052 | Start, stop and change limits from the app. | Device follows each command; config persists after reboot. |
| TC-Cfg-01 | F-060 | Change interface default, limits and alert thresholds. | New values applied on the next session and detector run. |
| TC-Cfg-02 | F-061 | Admin creates, changes role of and disables accounts. | Disabled account cannot log in; role change takes effect on next token. |
| TC-Cfg-03 | F-062 | Compare health view with ground truth (fuel gauge, df, uptime). | Battery within 5 points; storage and uptime exact. |
| TC-Perf-01 | NF-001 | tcpreplay at 100, 500 and 1000 pkt/s with sequence-tagged frames; record device capture time and app display time for 10,000 packets. | p90 latency of 1 s or less at every rate up to 1000 pkt/s. |
| TC-Rel-01 | NF-003 | 1000 pkt/s for 10 min on a fixed channel; compare PPS count with the reference sniffer and libpcap drop counters. | Loss of 1% or less relative to the reference sniffer. |
| TC-Power-01 | NF-002 | Full charge; continuous capture at 200 pkt/s with the app connected; log battery every minute. | At least 4 h before low-battery shutdown. |
| TC-UX-01 | NF-004 | At least 5 first-time users: pair, start a filtered capture, find a DNS query, export the PCAP. No help given. | At least 80% complete unaided. SUS score recorded for information. |
| TC-Port-01 | NF-005 | Build and run the unmodified source on the second SBC; run TC-Cap-01, TC-Cap-02 and TC-Dec-01. | All three pass with no source changes. |
| TC-Maint-01 | NF-006 | Run import-linter contracts; add a dummy protocol decoder plug-in. | Contracts pass; plug-in needs changes only in decode/plugins. |
| TC-Sec-01 .. 05 | SR-001 .. 005 | As described in Section 5.1. | As per SRS 5.1.2 acceptance criteria. |
| TC-Rob-01 | F-010 | Feed 100,000 malformed / truncated frames (Scapy fuzz) to the decoder. | No crash; no packet takes more than 100 ms; errors counted. |
| TC-Rob-02 | SR-004 | schemathesis run against the OpenAPI schema with each role. | No 5xx responses; all errors use the standard envelope. |


### 14. Test Metrics & Reporting
Metrics collected:
- % test cases executed
- % passed / failed / blocked
- Requirement coverage (requirements with at least one passing test / total)
- Defect density (defects per module) and defect aging
- NF measurements: p90 latency, % packet loss, battery runtime (hours)
Reports:
- Execution status after each cycle, shared with the Project Guide
- Final Test Summary Report with the updated RTM

### 15. Approvals

| Role | Name | Signature / Date |
|---|---|---|
| QA Lead |  |  |
| Dev Lead |  |  |
| Project Guide (Product Owner) |  |  |


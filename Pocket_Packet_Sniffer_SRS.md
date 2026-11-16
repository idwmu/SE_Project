# Software Requirements Specification (SRS)

**Project:** Pocket Packet Sniffer (PPS)
**Version:** 1.0
**Date:** 17-11-2026
**Status:** Final v1.0

## Revision history

| Version | Date | Change summary |
|---|---|---|
| 1.0 | 8-09-2026 | Initial SRS for the Pocket Packet Sniffer mini project |

## 1. Introduction

### 1.1 Purpose
This SRS defines the functional and non-functional requirements, interfaces and verification criteria of the Pocket Packet Sniffer (PPS), a network packet capture and analysis tool controlled from a web dashboard. It guides design, implementation and evaluation, and it is the baseline for the SAD and the Test Plan.

### 1.2 Scope
PPS covers: capture from a network interface or replay of a PCAP file; protocol decoding; capture and display filters; local storage and PCAP export; anomaly detection (ARP spoofing, port scans) with alerts; a secured web dashboard with pairing, accounts and roles; device configuration and a health view; and an audit log.

Excluded: active intrusion prevention (blocking or dropping traffic), decryption of encrypted payloads, and capture on networks the user is not authorised to monitor. Handheld hardware (enclosure, battery, OLED, LEDs, buttons, BLE) is out of scope for this release.

### 1.3 Audience
Developers, QA engineers, the course coordinator and project guide, and assessment evaluators.

### 1.4 Definitions
PPS (Pocket Packet Sniffer), NIC (network interface card), PCAP (packet capture file format), BPF (Berkeley Packet Filter), ARP, TCP, UDP, ICMP, DNS, HTTP, TLS, API, UI, PIN, RBAC (role-based access control), TTL (time to live), MITM (man in the middle), p90 (90th percentile), RTM (requirements traceability matrix), SQLite (embedded database).

## 2. Overall description

### 2.1 Product perspective
PPS is a self-contained Python service. It captures and decodes traffic on the host it runs on, stores sessions in a local SQLite database and PCAP files, and serves a web dashboard and a REST and WebSocket API over HTTPS. It runs on Windows and Linux with Python 3.10 or later. Live capture needs Npcap (Windows) or libpcap (Linux and macOS); replay needs neither.

### 2.2 Major product functions
- Select a capture source (network interface or replay file) and start and stop capture
- Decode Ethernet, IPv4, IPv6, TCP, UDP, ICMP and ARP, and label DNS and HTTP
- Apply BPF capture filters and combinable display filters, and save filters as presets
- Show live statistics (packet and byte counts, top talkers, protocol mix)
- Store each session as a standard PCAP file and export it
- Detect ARP spoofing and port scans and raise timestamped alerts pushed to the dashboard
- Pair a browser with a PIN, and control the service from the dashboard
- Configure limits, thresholds and storage; manage user accounts
- Show device health (battery where available, storage, uptime, CPU, memory)
- Authenticate users, enforce roles and keep a tamper-evident audit log
- Manage storage by rotating the oldest sessions and warning when space is low

### 2.3 User roles and characteristics

| Role | Description | Privileges |
|---|---|---|
| Trainee | Student using a guided, read-only view for learning | View live traffic, sessions, packets, alerts, settings and health; download PCAPs; validate filters |
| Analyst | Network technician with basic to intermediate networking knowledge | Trainee privileges, plus start and stop captures, upload replay files, list interfaces, acknowledge alerts, save and delete filter presets |
| Administrator | Configures the service and manages users | Analyst privileges, plus change settings, manage users and roles, delete sessions, view and verify the audit log |

### 2.4 Operating environment
Windows 10 or later, or Linux, with Python 3.10 or later. A modern web browser (Chrome, Edge or Firefox) as the client. Npcap or libpcap for live capture. Network access between the browser and the service (the same machine or a LAN).

### 2.5 Constraints
- Capture only on networks the user is authorised to monitor; live capture requires an explicit confirmation.
- Live capture needs administrator rights on most systems.
- One capture session runs at a time.
- Storage is limited by a configurable quota (default 500 MB).
- 802.11 monitor mode depends on adapter and driver support and is not required for this release.

### 2.6 Assumptions and dependencies
Python packages: Scapy, FastAPI, Uvicorn, python-multipart, cryptography, psutil. SQLite from the Python standard library. The development and test tools are pytest, httpx, ruff and import-linter.

## 3. External interface requirements

### 3.1 User interfaces
A single-page web dashboard served by the service, with tabs for Live capture, Sessions, Alerts, Settings, Admin and Device health. The tabs shown depend on the user's role.

### 3.2 Hardware interfaces
A network interface that supports promiscuous capture (live mode). No other hardware is required.

### 3.3 Software interfaces
- Scapy with Npcap or libpcap for capture and PCAP reading and writing
- Local SQLite database for sessions, alerts, presets, users, audit log and configuration
- REST API under `/api/v1` and a WebSocket at `/api/v1/ws/live`, using JSON

### 3.4 Communications
- HTTPS with a self-signed certificate generated on first start; the SHA-256 fingerprint is shown at start-up
- A 6-digit PIN shown at start-up pairs a browser with the service
- The dashboard reconnects the WebSocket with backoff after a connection loss

## 4. System features (detailed)

Status values: **Implemented** (built and verified), **Partial** (built with a stated limit), **Deferred** (not in this release). Test cases are named in the Test Plan v1.0.

### 4.1 Capture control

| Req ID | Requirement (the system shall...) | Type | Priority | Acceptance criteria and test | Status |
|---|---|---|---|---|---|
| PPS-F-001 | List the available network interfaces and let the user select one as the capture source; where the platform supports it, report and switch monitor mode | Functional | High | Interfaces are listed; an unsupported mode returns a clear error. TC-Cap-01 | Partial (promiscuous capture; monitor mode checked on Linux only, not on a real adapter) |
| PPS-F-002 | Start a capture on demand and stop it on demand or at a configured duration or packet-count limit | Functional | High | Start and stop acknowledged within 2 s; limits respected; a second start while running is refused. TC-Cap-02 | Implemented |
| PPS-F-003 | Show a capture-status indicator (idle, starting, active, stopping, error) in the dashboard | Functional | Medium | Indicator reflects the true state within 1 s. TC-Cap-03 | Implemented |
| PPS-F-004 | Replay a stored or uploaded PCAP file through the same pipeline as live capture, at a chosen speed | Functional | Medium | Replay yields the same packet count as the file. TC-Cap-02 | Implemented |

### 4.2 Protocol decoding

| Req ID | Requirement | Type | Priority | Acceptance criteria and test | Status |
|---|---|---|---|---|---|
| PPS-F-010 | Decode Ethernet, IPv4, IPv6, TCP, UDP, ICMP and ARP headers for each captured packet | Functional | High | Decoded fields match the known values for sample PCAPs; malformed frames never crash the decoder. TC-Dec-01, TC-Rob-01 | Implemented |
| PPS-F-011 | Label DNS and HTTP packets where recognisable from ports and signatures | Functional | Medium | At least 95% of DNS and HTTP packets in the test set are labelled. TC-Dec-02 | Implemented |

### 4.3 Filtering and search

| Req ID | Requirement | Type | Priority | Acceptance criteria and test | Status |
|---|---|---|---|---|---|
| PPS-F-020 | Support BPF capture filters on live capture and reject an invalid expression before capture starts | Functional | High | A valid filter captures only matching packets; an invalid one returns `BPF_INVALID`. TC-Filt-01 | Implemented (live capture only; replay uses display filters) |
| PPS-F-021 | Support display filters and search by IP address, port, protocol and MAC address | Functional | High | Each condition returns the expected packets. TC-Filt-02 | Implemented |
| PPS-F-022 | Allow filters to be combined with AND, OR, NOT and brackets | Functional | Medium | Combined expressions return the expected packets; invalid syntax returns an error. TC-Filt-03 | Implemented |
| PPS-F-023 | Allow filters to be saved, listed, replaced and deleted as presets | Functional | Low | Presets persist across restarts. TC-Filt-04 | Implemented |

### 4.4 Storage and export

| Req ID | Requirement | Type | Priority | Acceptance criteria and test | Status |
|---|---|---|---|---|---|
| PPS-F-030 | Persist every capture session as a standard PCAP file with session metadata in SQLite | Functional | High | The PCAP re-reads with the same packet count as the session summary. TC-Sto-01 | Implemented |
| PPS-F-031 | Let an authorised user download a session's PCAP from the dashboard | Functional | High | The downloaded file is byte-identical to the stored file (SHA-256). TC-Sto-02 | Implemented |
| PPS-F-032 | Rotate the oldest finished sessions when storage exceeds the configured quota, never removing an active session | Functional | Medium | Oldest sessions are removed first. TC-Sto-03 | Implemented |
| PPS-F-033 | Archive older sessions | Functional | Low | Archived sessions remain listed and exportable. TC-Sto-04 | Deferred |
| PPS-F-034 | Warn when free storage falls below a configurable threshold | Functional | Medium | A warning is shown in the dashboard. TC-Sto-05 | Implemented |

### 4.5 Anomaly detection and alerting

| Req ID | Requirement | Type | Priority | Acceptance criteria and test | Status |
|---|---|---|---|---|---|
| PPS-F-040 | Detect ARP spoofing (an IP address seen with a second MAC address), with a whitelist for legitimate changes | Functional | High | Spoofing raises an alert; normal traffic raises none; whitelisted changes are ignored. TC-Anom-01 | Implemented |
| PPS-F-041 | Detect port scans (one source contacting at least a configured number of ports within a configured window, default 20 ports in 10 s) | Functional | High | A scan raises an alert; the threshold is configurable; repeat alerts are rate-limited (default 60 s). TC-Anom-02 | Implemented |
| PPS-F-042 | Detect rogue access points (unexpected BSSIDs on known SSIDs) | Functional | Medium | A rogue BSSID raises an alert. TC-Anom-03 | Deferred (needs 802.11 beacon capture) |
| PPS-F-043 | Store each alert with a timestamp and push it to the dashboard in real time; allow acknowledgement | Functional | High | Every alert is stored and shown within 2 s. TC-Anom-04 | Implemented |

### 4.6 Remote access and dashboard control

| Req ID | Requirement | Type | Priority | Acceptance criteria and test | Status |
|---|---|---|---|---|---|
| PPS-F-050 | Pair a browser with the service using a PIN | Functional | High | Pairing succeeds only with the correct PIN; the browser then stays paired. TC-App-01, TC-Sec-01 | Partial (PIN only; QR and BLE pairing deferred) |
| PPS-F-051 | Stream live capture summaries (packets, statistics, alerts, state) to the dashboard | Functional | High | The dashboard updates every 250 ms and counters match the service. TC-App-02 | Implemented |
| PPS-F-052 | Allow capture start, stop and configuration from the dashboard | Functional | High | The service follows each command. TC-App-03 | Implemented |

### 4.7 Device configuration and management

| Req ID | Requirement | Type | Priority | Acceptance criteria and test | Status |
|---|---|---|---|---|---|
| PPS-F-060 | Provide configuration of default interface, duration and packet limits, alert thresholds, ARP whitelist and storage quota | Functional | Medium | New values apply to the next session. TC-Cfg-01 | Implemented |
| PPS-F-061 | Let an administrator create users, change roles, disable users and reset passwords | Functional | Medium | A disabled user cannot log in; a role change applies on the next request; the last active administrator cannot be removed. TC-Cfg-02 | Implemented |
| PPS-F-062 | Provide a device health view (battery where available, storage used, uptime, CPU, memory) | Functional | Medium | Values match the operating system. TC-Cfg-03 | Implemented |

## 5. Non-functional requirements

| Req ID | Requirement | Category | Priority | Acceptance criteria and test | Status |
|---|---|---|---|---|---|
| PPS-NF-001 | Decode and display packets with a live-view latency of 1 s or less at p90, at up to 1000 packets per second | Performance | High | p90 at most 1 s. TC-Perf-01 | Implemented (measured about 225 to 230 ms with replayed traffic) |
| PPS-NF-002 | Sustain a continuous capture of at least 4 hours on a full battery | Reliability and power | High | TC-Power-01 | Deferred (battery-powered hardware not part of this release) |
| PPS-NF-003 | Lose no more than 1% of packets at the rated throughput (taken as 1000 packets per second) | Reliability | High | Loss at most 1%. TC-Rel-01 | Implemented (0.00% with replayed traffic) |
| PPS-NF-004 | Present live traffic and filters with a layout usable by a first-time user without training | Usability | Medium | At least 80% of first-time users complete a guided task. TC-UX-01 | Not measured (no user study) |
| PPS-NF-005 | Run unmodified on Windows and Linux with Python 3.10 and 3.12 | Portability | Medium | Automated tests pass in CI on Linux with Python 3.10 and 3.12; development on Windows. TC-Port-01 | Implemented |
| PPS-NF-006 | Be modular: capture, decode, filter, storage, alerting and API as separate components, with the packet logic independent of the API | Maintainability | Medium | import-linter contracts pass. TC-Maint-01 | Implemented |

### 5.1 Security

#### 5.1.1 Security objectives
- Only authorised users and browsers can pair with and control PPS.
- Control traffic is encrypted in transit.
- Security-relevant events are recorded in a tamper-evident log.

#### 5.1.2 Security requirements

| Req ID | Requirement | Priority | Acceptance criteria and test | Status |
|---|---|---|---|---|
| PPS-SR-001 | Pairing shall require a PIN and shall reject unauthenticated connections; repeated wrong PINs and wrong passwords shall cause a temporary lockout (5 failures, 300 s) | High | Pairing without the PIN is refused; lockout applies. TC-Sec-01 | Implemented |
| PPS-SR-002 | All control-API traffic shall be encrypted with TLS | High | A capture of API traffic shows no plaintext payloads. TC-Sec-02 | Implemented (self-signed certificate) |
| PPS-SR-003 | Stored captures and credentials shall be protected at rest. Passwords are stored only as scrypt hashes; client tokens only as SHA-256 digests | High | TC-Sec-03 | Partial (credentials protected; capture files not encrypted) |
| PPS-SR-004 | Enforce role-based access control for the roles trainee, analyst and administrator on every route | Medium | A lower role is refused administrator actions. TC-Sec-04 | Implemented |
| PPS-SR-005 | Keep a tamper-evident audit log of pairing, authentication, configuration and user changes, capture start and end, and alerts | Medium | Entries exist for each event type; editing or deleting an entry makes verification fail. TC-Sec-05 | Implemented (SHA-256 hash chain) |

Additional security behaviour: access tokens last 1 hour and are held in memory; client tokens last 30 days; live capture requires explicit confirmation that the user is authorised.

## 6. Quality attributes and acceptance

Exit criteria: all high-priority functional requirements implemented and verified, no critical non-functional failure, and the RTM shows the listed test cases passed or the deviation recorded. Acceptance suites: capture control, protocol decoding, filtering and storage, anomaly detection and alerting, dashboard and pairing, performance, security, robustness.

## 7. System models

### 7.1 Use cases

| Actor | Use cases |
|---|---|
| Analyst | Select source, start and stop capture, view live traffic, apply filters, acknowledge alerts, download PCAP, save filter presets |
| Administrator | All analyst use cases, plus configure settings, manage users and roles, view the audit log, delete sessions |
| Trainee | View live traffic, sessions, alerts, settings and health; download PCAP |
| System | Decode packets, detect anomalies, store sessions, rotate old sessions, write audit entries |

### 7.2 Data and architecture
See the SAD: layered monolith, event bus between capture and the web layer, SQLite tables `sessions`, `alerts`, `presets`, `users`, `audit_log`, `config`.

## 8. Requirements traceability matrix

| Req ID | Requirement (short) | Module | Test case(s) | Status |
|---|---|---|---|---|
| PPS-F-001 | Select interface | `interfaces.py`, `routes_capture.py` | TC-Cap-01 | Partial |
| PPS-F-002 | Start and stop, limits | `capture.py` | TC-Cap-02 | Implemented |
| PPS-F-003 | Status indicator | `capture.py`, `live.js` | TC-Cap-03 | Implemented |
| PPS-F-004 | PCAP replay | `capture.py`, `routes_capture.py` | TC-Cap-02 | Implemented |
| PPS-F-010 | Decode headers | `decode.py` | TC-Dec-01, TC-Rob-01 | Implemented |
| PPS-F-011 | DNS and HTTP labels | `applabel.py` | TC-Dec-02 | Implemented |
| PPS-F-020 | BPF capture filter | `bpf.py`, `capture.py` | TC-Filt-01 | Implemented |
| PPS-F-021 | Display filters | `displayfilter.py` | TC-Filt-02 | Implemented |
| PPS-F-022 | Combined filters | `displayfilter.py` | TC-Filt-03 | Implemented |
| PPS-F-023 | Filter presets | `storage.py`, `routes_filters.py` | TC-Filt-04 | Implemented |
| PPS-F-030 | Persist as PCAP | `capture.py`, `storage.py` | TC-Sto-01 | Implemented |
| PPS-F-031 | Download PCAP | `routes_capture.py` | TC-Sto-02 | Implemented |
| PPS-F-032 | Rotation | `storage.py` | TC-Sto-03 | Implemented |
| PPS-F-033 | Archival | none | TC-Sto-04 | Deferred |
| PPS-F-034 | Low-space warning | `storage.py`, `capture.py` | TC-Sto-05 | Implemented |
| PPS-F-040 | ARP spoofing | `detectors.py` | TC-Anom-01 | Implemented |
| PPS-F-041 | Port scan | `detectors.py` | TC-Anom-02 | Implemented |
| PPS-F-042 | Rogue AP | none | TC-Anom-03 | Deferred |
| PPS-F-043 | Alert delivery | `capture.py`, `bus.py`, `routes_capture.py`, `alerts.js` | TC-Anom-04 | Implemented |
| PPS-F-050 | Pairing | `auth.py`, `routes_auth.py` | TC-App-01, TC-Sec-01 | Partial |
| PPS-F-051 | Live stream | `routes_capture.py` (WebSocket) | TC-App-02 | Implemented |
| PPS-F-052 | Remote control | `routes_capture.py`, `routes_config.py` | TC-App-03 | Implemented |
| PPS-F-060 | Configuration | `routes_config.py`, `settings.py` | TC-Cfg-01 | Implemented |
| PPS-F-061 | User management | `auth.py`, `routes_auth.py` | TC-Cfg-02 | Implemented |
| PPS-F-062 | Health view | `health.py`, `routes_health.py` | TC-Cfg-03 | Implemented |
| PPS-NF-001 | Latency | `bus.py`, WebSocket batching | TC-Perf-01 | Implemented |
| PPS-NF-002 | 4 h battery | none | TC-Power-01 | Deferred |
| PPS-NF-003 | Packet loss | `capture.py`, `bus.py` | TC-Rel-01 | Implemented |
| PPS-NF-004 | Usability | dashboard | TC-UX-01 | Not measured |
| PPS-NF-005 | Portability | whole code base, CI | TC-Port-01 | Implemented |
| PPS-NF-006 | Modularity | import-linter contracts | TC-Maint-01 | Implemented |
| PPS-SR-001 | Authenticated pairing | `auth.py` | TC-Sec-01 | Implemented |
| PPS-SR-002 | Encrypted API | `tlsutil.py` | TC-Sec-02 | Implemented |
| PPS-SR-003 | Protection at rest | `auth.py`, `storage.py` | TC-Sec-03 | Partial |
| PPS-SR-004 | RBAC | `auth.py`, `deps.py` | TC-Sec-04 | Implemented |
| PPS-SR-005 | Audit log | `storage.py`, `routes_audit.py` | TC-Sec-05 | Implemented |
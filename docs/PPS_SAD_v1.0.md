# Software Architecture Document (SAD) - Pocket Packet Sniffer (PPS)

**Project:** Pocket Packet Sniffer (PPS)
**Version:** 1.0 (as built)
**Status:** Draft, reconstructed from the v1.0 code on `main`

> Note on provenance. The original SAD v1.0 (22-10-2026) is not in the repository. This document was regenerated from the code and `docs/DEVIATIONS.md`, so it describes the system as built. Where the original SAD decision differs, the change is listed in section 10. Replace this file with the original if the course requires the submitted version.

## 1. Introduction

### 1.1 Purpose
This document describes the architecture of PPS: its structure, data flow, interfaces, data storage, security design and the reasons behind the main decisions. It supports the SRS v1.0 and the Test Plan v1.0.

### 1.2 Scope
PPS captures packets from a network interface (or replays a PCAP file), decodes them, applies filters, stores sessions, detects ARP spoofing and port scans, and serves a web dashboard over HTTPS to authenticated users with roles. It does not block traffic, decrypt payloads or capture on networks the user is not authorised to monitor.

### 1.3 References
SRS v1.0 (08-09-2026); Test Plan v1.0 (22-10-2026); `docs/DEVIATIONS.md`; `docs/TEST_REPORT.md`; `docs/PR_PLAN.md`.

## 2. Architectural drivers

| Driver | Source | Effect on the design |
|---|---|---|
| Modularity: capture, decode, storage, alerting and API as separate components | PPS-NF-006 | Packet logic has no web imports; import-linter enforces two contracts in CI |
| Live-view latency of 1 s or less at up to 1000 pkt/s | PPS-NF-001 | Event bus plus 250 ms WebSocket batching |
| Packet loss of 1% or less | PPS-NF-003 | PCAP written first; bounded queues so a slow client never blocks capture |
| Authenticated, encrypted, role-based, audited control channel | PPS-SR-001, 002, 004, 005 | PIN pairing, HTTPS, token auth, RBAC, hash-chained audit log |
| Local storage and standard export | PPS-F-030, F-031 | SQLite for metadata, one standard PCAP per session |
| Runs on commodity hardware, no build step | Team constraint | Python 3.10+, one process, vanilla JavaScript front end |

## 3. Architecture overview

### 3.1 Style
A layered monolith in one Python process, with an in-process publish and subscribe event bus between the capture service and the web layer.

### 3.2 Layers

| Layer | Responsibility | Code |
|---|---|---|
| Presentation | Dashboard tabs, WebSocket client with reconnect and backoff | `pps/static/` |
| API and security | HTTP routes, role check, token check, error envelope | `pps/api/`, `pps/auth.py` |
| Application services | Capture manager, event bus, alert engine, live stats, health | `capture.py`, `bus.py`, `detectors.py`, `stats.py`, `health.py` |
| Packet logic | Decoder, application labels, BPF check, display filter | `decode.py`, `applabel.py`, `bpf.py`, `displayfilter.py` |
| Data | SQLite database and PCAP files | `storage.py` |
| Platform | Npcap or libpcap, network interface, TLS certificate | Operating system, `tlsutil.py`, `interfaces.py` |

### 3.3 Components and dependencies
`core.Core` creates one `Storage`, one `EventBus`, one `AuthService` and one `CaptureManager` and passes them to the API through the application state. There are no global singletons.

Dependency rules, checked by `lint-imports` in CI:
1. Core modules (decode, applabel, bpf, displayfilter, detectors, stats, capture, storage, auth, bus) never import `pps.api`.
2. Decode, display filter and detectors do not import capture, storage or auth.

## 4. Data flow (pipeline)

1. A source feeds packets to `CaptureManager._on_packet`: a Scapy `AsyncSniffer` on a live interface, or a replay thread reading a PCAP with its original gaps divided by the replay speed.
2. The raw packet is written to the session's PCAP file.
3. `decode()` builds a `DecodedPacket`; `applabel` adds DNS and HTTP labels.
4. `LiveStats` updates packet and byte counts, top talkers and protocol mix.
5. `AlertEngine` runs the ARP spoofing and port-scan detectors. Each alert is saved to SQLite, written to the audit log and published on the bus.
6. The decoded packet is published on the bus with a timestamp.
7. The `/ws/live` WebSocket drains its subscription every 250 ms, applies the client's display filter and sends one batch (packets, events, status).
8. When the session ends, the session row is closed, old sessions are rotated if the storage quota is exceeded, and a low-storage warning is published if space is low.

### 4.1 Capture state machine
States: `IDLE`, `STARTING`, `ACTIVE`, `STOPPING`, `ERROR`. Only one session runs at a time (a second start returns HTTP 409 `CAPTURE_ACTIVE`). A session ends on user stop, duration limit, packet limit, end of replay file, or error.

### 4.2 Event bus
`EventBus.publish(topic, item)` pushes to each subscriber's bounded queue. Topics: `packet`, `alert`, `state`, `warning`. When a queue is full the oldest items are dropped and counted, so capture never waits for a slow browser.

## 5. Data design

### 5.1 SQLite tables (`storage.py`)

| Table | Key columns | Purpose |
|---|---|---|
| `sessions` | `id`, `source`, `bpf`, `started`, `ended`, `packets`, `bytes`, `status`, `file`, `created_by`, `error` | One row per capture session |
| `alerts` | `id`, `session_id`, `type`, `severity`, `ts`, `message`, `details`, `acked` | Detected anomalies |
| `presets` | `name`, `expression`, `created_by`, `updated` | Saved display filters |
| `users` | `username`, `pw_hash`, `role`, `active`, `created` | Accounts and roles |
| `audit_log` | `id`, `ts`, `actor`, `action`, `details`, `prev_hash`, `hash` | Hash-chained security log |
| `config` | `key`, `value` | Runtime settings changed by an admin |

### 5.2 Files
One PCAP file per session in the captures folder. Replay files are kept in a separate replay folder. The TLS certificate and key are kept in the data folder.

### 5.3 Runtime configuration
Keys: `default_interface`, `max_duration_s`, `max_packets` (0 means no limit), `portscan_threshold` (default 20 ports), `portscan_window_s` (default 10 s), `arp_whitelist` (entries `ip=mac`), `max_storage_mb` (default 500), `low_space_warn_pct`, plus the realert interval (60 s). Defaults come from environment variables through `settings.py`.

### 5.4 Rotation
After each session, `Storage.rotate()` deletes the oldest finished sessions until the quota is met. It never removes the session just finished or an active one.

## 6. Interfaces

### 6.1 REST API (`/api/v1`)

| Method and path | Minimum role | Purpose |
|---|---|---|
| `POST /pair` | none | Exchange the PIN for a client token |
| `POST /auth/login` | paired client | Username and password for an access token |
| `GET /auth/me` | any signed-in user | Current user and role |
| `GET /users`, `POST /users`, `PATCH /users/{name}` | admin | Manage accounts |
| `GET /interfaces` | analyst | List capture interfaces |
| `GET /replay-files`, `POST /replay-files` | trainee (list), analyst (upload) | Replay PCAPs |
| `GET /capture/status` | trainee | Current state and live stats |
| `POST /captures`, `POST /captures/{id}/stop` | analyst | Start and stop |
| `GET /captures`, `/captures/{id}/packets`, `/captures/{id}/pcap` | trainee | Sessions, packets with display filter, PCAP download |
| `DELETE /captures/{id}` | admin | Delete a session |
| `POST /filters/validate` | trainee | Check a display or BPF filter |
| `GET /filters/presets`; `PUT`, `DELETE /filters/presets/{name}` | trainee (read), analyst (write) | Saved filters |
| `GET /alerts`; `POST /alerts/{id}/ack` | trainee; analyst | Alerts |
| `GET /config`; `PUT /config` | trainee; admin | Settings |
| `GET /device/health` | trainee | Battery, storage, uptime, CPU, memory |
| `GET /audit` | admin | Audit entries and chain verification |
| `GET /info` | none | Version information |

Errors use one envelope with a stable code (for example `PIN_INVALID`, `NOT_PAIRED`, `INVALID_CREDENTIALS`, `BPF_INVALID`, `CAPTURE_ACTIVE`, `NOT_FOUND`).

### 6.2 WebSocket `/api/v1/ws/live`
The client connects with its access token and an optional display filter, and may send `{filter: "..."}` to change it. The server sends `batch` messages every 250 ms with `seq`, `packets`, `received`, `events` and `status`, and `error` messages (`FILTER_INVALID`, auth errors, close code 4401).

### 6.3 Platform interfaces
Scapy to Npcap (Windows) or libpcap (Linux and macOS) for capture. On Linux `interfaces.py` calls `iw` and `ip` to read and switch monitor mode. `psutil` supplies device health.

## 7. Security architecture

| Concern | Mechanism | Requirement |
|---|---|---|
| Transport | HTTPS with a self-signed ECDSA certificate created on first run; the SHA-256 fingerprint is printed at start-up | PPS-SR-002 |
| Device pairing | 6-digit PIN printed at start-up (random unless `--pin`); success returns a random client token, stored server-side only as a SHA-256 digest, valid 30 days; 5 wrong PINs lock pairing for 300 s | PPS-SR-001 |
| Authentication | Username and password; passwords hashed with scrypt and a per-password salt; 1-hour access token held in memory; 5 failures lock the account for 300 s | PPS-SR-001, SR-004 |
| Authorisation | Roles `trainee` < `analyst` < `admin`; `require(role)` on every route; the role is read from the database on each request so changes apply immediately; the last active admin cannot be removed | PPS-SR-004 |
| Accountability | Audit log of pairing, logins, config changes, user changes, capture start and end, and alerts; each row stores `prev_hash` and `hash` (SHA-256 chain); `GET /audit` verifies the chain, so an edited or deleted row is detected | PPS-SR-005 |
| Capture ethics | Live capture needs an explicit "authorised to capture" confirmation (HTTP 412 `AUTHORISATION_REQUIRED` otherwise) | SRS 2.5 |
| Input safety | Replay file names are resolved inside the replay folder; session ids are validated; filters are parsed by our own parser, never evaluated as code | General |
| Not provided | Encryption at rest, CA-issued certificate, token refresh, configured HMAC key for the audit chain | D4, D15, D6, D11 |

First run: `bootstrap_admin()` creates the user `admin` with a random password shown once in the banner.

## 8. Deployment view
One process started by `python -m pps` (options `--port`, `--data-dir`, `--no-tls`, `--pin`). Uvicorn serves the API, the WebSocket and the static dashboard on one HTTPS port (default 8443). A data folder holds the SQLite file, captures, replay files and the certificate. A browser on the same machine or LAN is the only client.

```
Browser  --HTTPS-->  Uvicorn / FastAPI  -->  Core (capture, bus, auth, storage)
                                              |-- Scapy --> Npcap/libpcap --> NIC or PCAP file
                                              '-- SQLite + PCAP files (data folder)
```

## 9. Quality attribute strategies

| Attribute | Strategy | Evidence |
|---|---|---|
| Performance (NF-001) | Batching every 250 ms, bounded queues, PCAP written first | Benchmark p90 about 225 to 230 ms at 100, 500, 1000 pkt/s |
| Reliability (NF-003) | Drop-oldest bus, one writer thread, interrupted sessions recovered at start-up | 0.00% loss in the replay benchmark |
| Maintainability (NF-006) | Layered modules, `Core` wiring, import-linter contracts, ruff | 2 contracts kept in CI |
| Testability | Replay source makes capture deterministic; FastAPI test client | 372 automated tests |
| Security | Section 7 | `test_auth`, `test_api_auth`, `test_api_admin`, `test_storage` audit tests |
| Usability | Single-page dashboard, role-based tabs, toasts for warnings | Manual demo (no user study) |

## 10. Architecture decisions and deviations from the original SAD

| ID | Decision as built | Original plan | Reason |
|---|---|---|---|
| AD-1 | Promiscuous capture plus PCAP replay | 802.11 monitor mode on a USB adapter (D1) | No monitor-mode adapter on the development laptops |
| AD-2 | Scapy for capture and decoding, in a thread | pcapy-ng and dpkt in a separate process (D3) | One dependency for capture, decode and PCAP I/O |
| AD-3 | scrypt (standard library) | Argon2id (D5) | Avoids a native dependency that is awkward on Windows |
| AD-4 | 1-hour access token, no refresh | 15-minute token plus refresh token (D6) | Simpler for the demo |
| AD-5 | One opaque client token (`x-pps-client`) | Client id and secret from `/pair` (D7) | Simpler and equivalent for one browser per pairing |
| AD-6 | Hash-chained audit log, optional HMAC | Same, with HMAC key (D11) | Key management not configured |
| AD-7 | Roles admin, analyst, trainee | Administrator and standard user (D10) | SRS 2.3 also defines a trainee |
| AD-8 | Self-signed certificate, renewed before expiry | CA-issued certificate (D15) | No public hostname |

Not implemented: archival of old sessions (D9, F-033), rogue access point detection (D2, F-042), encryption at rest (D4, SR-003).

## 11. Traceability to the SRS

| Requirement | Architecture element |
|---|---|
| F-001, F-002, F-003 | `CaptureManager`, `interfaces.py`, `/captures`, status events |
| F-010, F-011 | `decode.py`, `applabel.py` |
| F-020 to F-023 | `bpf.py`, `displayfilter.py`, `presets` table, `/filters/*` |
| F-030, F-031, F-032, F-034 | PCAP writer, `/captures/{id}/pcap`, `Storage.rotate()`, `storage_status()` |
| F-040, F-041, F-043 | `detectors.py`, `alerts` table, bus topic `alert`, `/ws/live` |
| F-050 to F-052 | `/pair`, `/ws/live`, capture and config routes |
| F-060 to F-062 | `/config`, `/users`, `/device/health` |
| NF-001, NF-003 | Event bus, 250 ms batching, drop-oldest queues |
| NF-006 | Layering and import-linter contracts |
| SR-001 | `AuthService.pair()`, lockout |
| SR-002 | `tlsutil.py`, Uvicorn TLS |
| SR-004 | `require_role`, `require()` dependency |
| SR-005 | `audit_log` hash chain, `/audit` |

## 12. Risks and limits

- Live capture needs Npcap or libpcap and, on most systems, administrator rights.
- Performance figures come from replayed traffic on one machine, not a radio link.
- Windows runs of the test suite show 7 symlink errors and 2 certificate-creation race failures (D12); Linux CI passes.
- One capture session at a time.

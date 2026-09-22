# Software Requirements Specification (SRS)

**Project:** Pocket Packet Sniffer (PPS)

**Version:** 1.0

**Date:** 08-09-2026

**Status:** Draft v1.0

Revision history

| **Version** | **Date**   | **Author** | **Change summary**                                         | **Approval** |
|-------------|------------|------------|------------------------------------------------------------|--------------|
| 1.0         | 08-09-2026 | Team       | Initial SRS drafted for Pocket Packet Sniffer mini project |              |

Table of Contents

## 1. Introduction

## 2. Overall description

## 3. External interfaces

## 4. System features (detailed)

## 5. Non-functional requirements (detailed)

## 6. Quality attributes & Acceptance tests

## 7. UML Use-Case Diagram

## 8. Requirements Traceability Matrix (RTM)

## 1. Introduction

### 1.1. Purpose

This document is a Software Requirements Specification (SRS) for the
Pocket Packet Sniffer (PPS), a portable, handheld network packet capture
and analysis tool. It defines the functional and non-functional
requirements, interfaces, and verification criteria intended to guide
design, implementation, and evaluation of the mini project.

### 1.2. Scope

Covers on-device packet capture in monitor/promiscuous mode over a Wi-Fi
network interface, protocol decoding, local filtering and storage, a
companion mobile/web application for control and visualisation, and
anomaly detection with alerting. Excludes active network
intrusion-prevention actions (blocking/dropping traffic), decryption of
encrypted payloads, and any capture performed on networks without the
owner's authorisation.

### 1.3. Audience

Developers, QA Engineers, Course Coordinator/Project Guide, and
Assessment Evaluators.

### 1.4. Definitions

List of acronyms: PPS (Pocket Packet Sniffer), NIC (Network Interface
Card), PCAP (Packet Capture file format), ARP, TCP, UDP, ICMP, DNS,
HTTP, BLE (Bluetooth Low Energy), OUI (Organisationally Unique
Identifier), TTL (Time To Live), MITM (Man-in-the-Middle), API, UI, TLS.

## 2. Overall description

### 2.1. Product perspective

The PPS is a self-contained, battery-powered handheld device (e.g.
Raspberry Pi Zero / ESP32 class hardware) fitted with a Wi-Fi adapter
capable of monitor mode. It captures and decodes traffic locally and
exposes a control/visualisation interface to a companion mobile or web
application over a local Wi-Fi hotspot or Bluetooth Low Energy (BLE)
pairing link.

### 2.2. Major product functions (detailed)

- Select capture interface and start/stop packet capture

- Decode common protocol headers (Ethernet, IP, TCP, UDP, ICMP, ARP,
  DNS, HTTP)

- Apply capture/display filters (BPF-style filter expressions)

- Live traffic statistics (packet counts, bandwidth, top
  talkers/protocols)

- Store captures locally and export as standard PCAP files

- Detect common network anomalies (ARP spoofing, port scans, rogue
  access points)

- Generate and push alerts to the companion app on anomaly detection

- Pair with and be controlled from a companion mobile/web application

- Device configuration (interface selection, capture duration, alert
  thresholds)

- Session summary report generation

- User authentication and role-based access to the device/app

- Storage management (rotation/archival of old capture files on microSD)

### 2.3. User roles and characteristics (expanded)

- Network Analyst/Technician: basic-to-intermediate networking
  knowledge; needs quick access to live traffic and clear protocol
  breakdowns in the field.

- Administrator: configures the device, manages users and alert rules,
  and reviews audit logs.

- Student/Trainee: uses the device for learning purposes with a
  simplified guided interface.

### 2.4. Operating environment

Embedded Linux (e.g. Raspberry Pi OS) or microcontroller firmware
(ESP32), a monitor-mode-capable Wi-Fi NIC, battery power with a charging
circuit, microSD storage, and a companion Android/iOS or web application
communicating over local Wi-Fi or BLE.

### 2.5. Constraints

Limited on-device compute, memory and storage; battery-life limitations;
legal/ethical constraints requiring capture only on networks the user is
authorised to monitor; microSD storage capacity; and dependency on Wi-Fi
adapters/drivers that support monitor mode.

## 3. External interface requirements

### 3.1. User interfaces

Primary UI: companion mobile/web application dashboard with live packet
view, filters, and alerts. Optional on-device UI: small OLED/LCD status
screen and physical buttons for start/stop capture without the companion
app.

### 3.2. Hardware interfaces

- Wi-Fi NIC supporting monitor/promiscuous mode (802.11)

- microSD card slot for capture storage

- Battery and charging circuit with charge-level sensing

- Status LEDs and physical control buttons

- Optional small OLED/LCD display

### 3.3. Software interfaces

- libpcap-based capture engine and protocol parser modules

- Local REST/WebSocket API exposed to the companion app for control and
  live data streaming

- Local SQLite database for capture metadata and session/alert history

### 3.4. Communications

- Local Wi-Fi hotspot or BLE for companion-app pairing, secured via
  PIN/QR pairing

- TLS used for the local control API where the platform supports it

- Reconnection/backoff strategy for companion-app connectivity

## 4. System features (detailed)

*Each requirement below includes acceptance criteria and a reference
test case. IDs follow PPS-F-###.*

### 4.1. Capture Control

*Description: Allow the user to select a capture interface and
start/stop packet capture sessions.*

| **Req ID** | **Requirement (shall...)**                                                                                                    | **Type**   | **Priority** | **Source/Stakeholder** | **Acceptance criteria / Test case ref**                                                      | **Comments / Dependencies**          |
|------------|-------------------------------------------------------------------------------------------------------------------------------|------------|--------------|------------------------|----------------------------------------------------------------------------------------------|--------------------------------------|
| PPS-F-001  | The system shall allow the user to select an available Wi-Fi interface and switch it into monitor mode before capture begins. | Functional | High         | Analyst                | AC-PPS-F-001: Selected interface enters monitor mode without error. Test: TC-Cap-01          | Requires monitor-mode-capable driver |
| PPS-F-002  | The system shall start a capture session on demand and stop it on demand or after a configured duration/packet-count limit.   | Functional | High         | Analyst                | AC-PPS-F-002: Capture starts/stops within 2s of command; limit is respected. Test: TC-Cap-02 | None                                 |
| PPS-F-003  | The system shall display a visible capture-status indicator (active/idle) on the device and companion app.                    | Functional | Medium       | Analyst                | AC-PPS-F-003: Status indicator reflects true capture state within 1s. Test: TC-Cap-03        | Depends on PPS-F-002                 |

### 4.2. Protocol Decoding

*Description: Decode captured frames into human-readable protocol fields
for common protocols.*

| **Req ID** | **Requirement (shall...)**                                                                                                       | **Type**   | **Priority** | **Source/Stakeholder** | **Acceptance criteria / Test case ref**                                                             | **Comments / Dependencies** |
|------------|----------------------------------------------------------------------------------------------------------------------------------|------------|--------------|------------------------|-----------------------------------------------------------------------------------------------------|-----------------------------|
| PPS-F-010  | The system shall decode Ethernet, IPv4/IPv6, TCP, UDP, ICMP and ARP headers for each captured packet.                            | Functional | High         | Analyst                | AC-PPS-F-010: Decoded fields match reference capture (Wireshark) for a sample pcap. Test: TC-Dec-01 | Core parser module          |
| PPS-F-011  | The system shall identify and label application-layer protocols (DNS, HTTP) where recognisable from well-known ports/signatures. | Functional | Medium       | Analyst                | AC-PPS-F-011: Correctly labels ≥95% of DNS/HTTP packets in test set. Test: TC-Dec-02                | Depends on PPS-F-010        |

### 4.3. Filtering & Search

Requirements: Support BPF-style capture filters and post-capture display
filters/search by IP, port, protocol, and MAC address. Filters shall be
combinable and saveable as presets. IDs: PPS-F-020..PPS-F-023.

### 4.4. Storage & Export

Requirements: Persist captures locally in PCAP format, support
export/download via the companion app, and manage storage via
rotation/archival of older sessions when microSD space is low, with a
warning threshold. IDs: PPS-F-030..PPS-F-034.

### 4.5. Anomaly Detection & Alerting

Requirements: Detect ARP spoofing (duplicate IP-to-MAC bindings),
port-scan patterns, and rogue access points (unexpected BSSIDs on known
SSIDs); generate a timestamped alert and push a notification to the
companion app for each detection. IDs: PPS-F-040..PPS-F-043.

### 4.6. Companion App / Remote Access

Requirements: Pair the companion app with the device over Wi-Fi/BLE
using a PIN or QR code, stream live capture summaries to the app, and
allow remote start/stop/configuration from the app. IDs:
PPS-F-050..PPS-F-052.

### 4.7. Device Configuration & Management

Requirements: Provide configuration for interface selection, capture
duration/limits, alert thresholds, and user accounts; provide a device
health view (battery level, storage used, uptime). IDs:
PPS-F-060..PPS-F-062.

## 5. Non-functional requirements (detailed)

*NFRs below are measurable and tied to test plans. IDs PPS-NF-###.*

| **Req ID** | **Requirement**                                                                                                                                      | **Category**      | **Priority** | **Acceptance criteria / Measurement**                                                   |
|------------|------------------------------------------------------------------------------------------------------------------------------------------------------|-------------------|--------------|-----------------------------------------------------------------------------------------|
| PPS-NF-001 | The system shall decode and display captured packets with a live-view latency of ≤ 1 second under normal traffic load (≤ 1000 pkt/s).                | Performance       | High         | 90th percentile latency ≤ 1s in bench test. Test: TC-Perf-01                            |
| PPS-NF-002 | The device shall sustain a continuous capture session of at least 4 hours on a full battery charge.                                                  | Reliability/Power | High         | Bench test confirms ≥4h runtime under typical load. Test: TC-Power-01                   |
| PPS-NF-003 | The system shall not lose more than 1% of packets during sustained capture at the rated maximum throughput.                                          | Reliability       | High         | Packet-loss measured against a reference capture ≤1%. Test: TC-Rel-01                   |
| PPS-NF-004 | The companion app UI shall present live traffic and filters with a layout usable by a first-time user without training.                              | Usability         | Medium       | Usability test: ≥80% of first-time users complete a guided task unaided. Test: TC-UX-01 |
| PPS-NF-005 | The capture engine shall run unmodified on at least two supported embedded hardware targets (e.g. Raspberry Pi and a generic Linux SBC).             | Portability       | Medium       | Successful build/run verified on both targets. Test: TC-Port-01                         |
| PPS-NF-006 | The codebase shall be modular (capture, decode, storage, alerting, API as separate components) to support maintenance and future protocol additions. | Maintainability   | Medium       | Architecture/code review confirms module boundaries. Test: TC-Maint-01                  |

### 5.1. Security

#### 5.1.1. Security Objectives

- Ensure only authorised users/devices can pair with and control the
  Pocket Packet Sniffer.

- Protect the confidentiality of captured traffic data and credentials
  stored on the device.

- Provide accountability via audit logging of security-relevant events.

#### 5.1.2. Security Requirements

| **Req ID** | **Requirement (shall...)**                                                                                                      | **Type** | **Priority** | **Acceptance criteria / Test case ref**                                                           |
|------------|---------------------------------------------------------------------------------------------------------------------------------|----------|--------------|---------------------------------------------------------------------------------------------------|
| PPS-SR-001 | Companion-app pairing shall require a PIN or QR-code exchange and shall reject unauthenticated connections.                     | Security | High         | AC-PPS-SR-001: Pairing without valid PIN/QR is refused. Test: TC-Sec-01                           |
| PPS-SR-002 | All control-API traffic between device and companion app shall be encrypted (TLS or equivalent) where the platform supports it. | Security | High         | AC-PPS-SR-002: Traffic capture shows no plaintext API payloads. Test: TC-Sec-02                   |
| PPS-SR-003 | Stored capture files and credentials shall be protected with access controls / encryption at rest on the microSD.               | Security | High         | AC-PPS-SR-003: Files unreadable without device credentials on removed microSD. Test: TC-Sec-03    |
| PPS-SR-004 | The system shall enforce role-based access control distinguishing Administrator and standard user privileges.                   | Security | Medium       | AC-PPS-SR-004: Standard user cannot access admin-only configuration. Test: TC-Sec-04              |
| PPS-SR-005 | The system shall maintain a tamper-evident audit log of authentication attempts, configuration changes, and alerts.             | Security | Medium       | AC-PPS-SR-005: Audit log entries created for each event type, verified in review. Test: TC-Sec-05 |

## 6. Quality attributes & Acceptance tests

Exit criteria for acceptance: all high-priority functional requirements
implemented and verified, no critical NFR failures, and the RTM shows
all listed test cases passed.

Acceptance test suites: Capture Control, Protocol Decoding, Filtering &
Storage, Anomaly Detection & Alerting, Companion App/Pairing,
Performance, and Security tests.

## 7. System models and diagrams

### 7.1. UML Use-Case diagram

Use-case diagram 1: Capture and analyse traffic (Network Analyst).

![](media/usecase-diagram-1-capture-analyse.png)

Use-case diagram 2: Security, pairing and device management
(Administrator / Companion App User).

![](media/usecase-diagram-2-security-pairing.png)

## 8. Requirements Traceability Matrix (RTM)

| **Req ID** | **Requirement (short)**         | **Section ref / Design Spec** | **Module**         | **Test case(s)** | **Status (N/P/A)** | **Comments** |
|------------|---------------------------------|-------------------------------|--------------------|------------------|--------------------|--------------|
| PPS-F-001  | Select interface / monitor mode | 4.1 / DS-Cap-01               | CaptureModule      | TC-Cap-01        | N                  |              |
| PPS-F-002  | Start/stop capture              | 4.1 / DS-Cap-01               | CaptureModule      | TC-Cap-02        | N                  |              |
| PPS-F-010  | Decode core protocol headers    | 4.2 / DS-Dec-01               | DecodeModule       | TC-Dec-01        | N                  |              |
| PPS-F-040  | Detect ARP spoofing / anomalies | 4.5 / DS-Alert-01             | AlertModule        | TC-Sec-anomaly   | N                  |              |
| PPS-F-050  | Pair companion app              | 4.6 / DS-App-01               | APIModule          | TC-Sec-01        | N                  |              |
| PPS-NF-001 | Live-view latency target        | 5 / DS-Perf-01                | UI / CaptureModule | TC-Perf-01       | N                  |              |
| PPS-NF-003 | Packet-loss target              | 5 / DS-Rel-01                 | CaptureModule      | TC-Rel-01        | N                  |              |
| PPS-SR-001 | Authenticated pairing           | 5.1.2 / DS-Sec-01             | APIModule          | TC-Sec-01        | N                  |              |
| PPS-SR-003 | Encryption at rest              | 5.1.2 / DS-Sec-03             | StorageModule      | TC-Sec-03        | N                  |              |

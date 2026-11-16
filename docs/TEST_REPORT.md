# Test report (against Test Plan v1.0)

## Test environment and execution results

Environment: Windows 11, Python 3.12, project virtual environment (`.venv`).

Commands executed:

- `pytest -q`
- `python -m ruff check pps tests tools`
- `lint-imports`
- `python -m py_compile tools/benchmark.py`
- `python tools/benchmark.py --rates 100 500 1000 --seconds 10`

Test suite result: **360 passed, 3 skipped, 7 errors, 2 failed**.

The seven errors in `tests/test_interfaces.py` occurred because Windows did not permit symbolic-link creation (`WinError 1314`). The two failures in `tests/test_tlsutil.py` occurred during concurrent certificate creation and involved Windows filesystem permission errors.

These failures are documented as platform-related test limitations. The repository CI runs the full test suite on Linux using Python 3.10 and Python 3.12; both CI jobs pass.

Static analysis:
- Ruff: All checks passed.
- Import-linter: 2 contracts kept, 0 broken.
- Python compilation of `tools/benchmark.py`: Passed.

Status: Pass = automated test passes; Manual = run by hand in the dashboard; Not run = see DEVIATIONS.md.

| Test case | Requirement | How it is verified | Status |
|---|---|---|---|
| TC-Cap-01 | F-001 | Interfaces listed in dashboard; live capture on loopback captured real traffic (manual) | Manual |
| TC-Cap-02 | F-002 | `test_api_capture.py::test_replay_capture_end_to_end` (start < 2 s), `test_packet_limit_respected`, `test_duration_limit_respected`, `test_manual_stop_and_conflict`, `test_capture.py` | Pass |
| TC-Cap-03 | F-003 | Status pill and state events (`test_capture.py::test_replay_writes_all_packets` checks state events) | Pass |
| TC-Dec-01 | F-010 | `test_decode.py` (Ethernet, IPv4, IPv6, TCP, UDP, ICMP, ARP fields) | Pass |
| TC-Dec-02 | F-011 | `test_applabel.py`, `test_decode.py::test_labelled_demo_set_accuracy` (>= 95% of DNS/HTTP labelled) | Pass |
| TC-Filt-01 | F-020 | `test_api_filters.py::test_validate_endpoint`; BPF on live capture checked manually with Npcap | Pass / Manual |
| TC-Filt-02 | F-021 | `test_displayfilter.py::test_single_conditions` (16 cases) | Pass |
| TC-Filt-03 | F-022 | `test_displayfilter.py::test_combinations` (8 cases) + invalid syntax (10 cases) | Pass |
| TC-Filt-04 | F-023 | `test_storage.py::test_presets_persist`, `test_api_filters.py::test_presets_crud` | Pass |
| TC-Sto-01 | F-030 | `test_capture.py::test_replay_writes_all_packets` (PCAP re-read, counts match) | Pass |
| TC-Sto-02 | F-031 | `test_api_capture.py::test_replay_capture_end_to_end` (SHA-256 of download = stored file) | Pass |
| TC-Sto-03 | F-032 | `test_storage.py::test_rotation_deletes_oldest_first`, `test_rotation_never_removes_active_session` | Pass |
| TC-Sto-04 | F-033 | Not implemented (D9) | Not run |
| TC-Sto-05 | F-034 | `test_storage.py::test_storage_warning_threshold`; dashboard toast | Pass |
| TC-Anom-01 | F-040 | `test_detectors.py::test_arp_spoof_detected`, `test_no_false_positives_on_normal_traffic`, `test_whitelisted_arp_change_is_ignored` | Pass |
| TC-Anom-02 | F-041 | `test_detectors.py::test_port_scan_detected`, `test_port_scan_threshold_configurable` | Pass |
| TC-Anom-03 | F-042 | Not implemented (D2) | Not run |
| TC-Anom-04 | F-043 | `test_api_alerts.py`, `test_api_capture.py::test_websocket_streams_packets_and_alerts` | Pass |
| TC-App-01 | F-050 | `test_api_auth.py` (pairing, wrong PIN, lockout); WebSocket reconnect with backoff in `core.js` (manual) | Pass / Manual |
| TC-App-02 | F-051 | `test_api_capture.py::test_websocket_streams_packets_and_alerts` (server-side live filter) | Pass |
| TC-App-03 | F-052 | `test_api_capture.py` start/stop/limits via API | Pass |
| TC-Cfg-01 | F-060 | `test_api_config.py::test_config_read_and_update`, `test_config_validation` | Pass |
| TC-Cfg-02 | F-061 | `test_api_auth.py::test_demotion_applies_immediately`, `test_api_admin.py::test_rbac_matrix` | Pass |
| TC-Cfg-03 | F-062 | `test_api_health.py::test_health_view` | Pass |
| TC-Perf-01 | NF-001 | `tools/benchmark.py` (results below) | Pass |
| TC-Rel-01 | NF-003 | `tools/benchmark.py` (results below) | Pass |
| TC-Power-01 | NF-002 | Battery-powered hardware is deferred in the SRS (PPS-NF-002) | Not run |
| TC-UX-01 | NF-004 | No user study yet | Not run |
| TC-Port-01 | NF-005 | CI runs on Python 3.10 and 3.12 (Linux); dev on Windows, where some tests fail (D12) | Partial |
| TC-Maint-01 | NF-006 | `lint-imports`: 2 contracts kept, 0 broken (core modules do not import the API; decoder/filters/detectors independent of capture, storage, auth) | Pass |
| TC-Sec-01 | SR-001 | `test_auth.py::test_pairing_lockout_and_recovery`, `test_api_auth.py::test_wrong_pin_rejected_and_lockout`, `test_login_requires_pairing` | Pass |
| TC-Sec-02 | SR-002 | HTTPS with self-signed certificate (manual check in browser / Wireshark) | Manual |
| TC-Sec-03 | SR-003 | Not implemented (D4) | Not run |
| TC-Sec-04 | SR-004 | `test_api_admin.py::test_rbac_matrix`, `test_auth.py::test_garbage_tokens_are_rejected` | Pass |
| TC-Sec-05 | SR-005 | `test_storage.py::test_audit_chain_detects_tampering`, `test_audit_chain_detects_deleted_entry`, `test_api_admin.py::test_audit_log_records_and_verifies` | Pass |
| TC-Rob-01 | F-010 | `test_robustness.py` (3000 fuzzed frames, no crash, < 100 ms each) | Pass |
| TC-Rob-02 | SR-004 | Error envelope checked across API tests; schemathesis run not done | Partial |

## Performance (TC-Perf-01, TC-Rel-01)

Command:

`python tools/benchmark.py --rates 100 500 1000 --seconds 10`

Actual benchmark results from the Windows development environment:

```text
 pkt/s    sent  captured  loss %   p50 ms   p90 ms   max ms  NF-001 / NF-003
   100    1000      1000    0.00    122.8    224.4    249.4  PASS
   500    5000      5000    0.00    131.5    227.9    394.2  PASS
  1000   10000     10000    0.00    132.6    230.5    384.2  PASS
```

All three packet rates satisfied the benchmark thresholds:

- PPS-NF-001: p90 latency <= 1000 ms.
- PPS-NF-003: packet loss <= 1%.

Latency is dominated by the 250 ms WebSocket batching interval (SAD 4.1), so p90 remains near 230 ms. These are replay results; live capture adds the NIC and driver, which this benchmark does not measure.

## Validation limitations

The full pytest run on Windows reported 360 passed, 3 skipped, 7 errors and 2 failures.

- The seven interface-test errors were caused by Windows symbolic-link permission restrictions (`WinError 1314`).
- The two TLS utility test failures involved permission errors during simultaneous certificate creation.
- Linux CI verification: the full test suite passes on Python 3.10 and Python 3.12.

Ruff and import-linter checks completed successfully in the Windows development environment.

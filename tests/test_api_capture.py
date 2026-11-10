"""TC-Cap-02, TC-Sto-01/02, TC-App-02/03 via the API.

Capture control, export, search and the live stream.
"""

import hashlib
import time

from scapy.utils import rdpcap

from .conftest import API, start_replay, wait_idle


def test_replay_capture_end_to_end(client, admin_h, app):
    t0 = time.time()
    st = start_replay(client, admin_h)
    assert time.time() - t0 < 2.0  # TC-Cap-02: start acknowledged within 2 s
    assert st["state"] in ("ACTIVE", "IDLE")
    st = wait_idle(client, admin_h)
    sess = st["session"]
    assert sess["status"] == "DONE" and sess["packets"] == len(
        rdpcap(str(app.state.core.settings.replay_dir / "demo_all.pcap"))
    )
    # export (TC-Sto-01/02): file opens and hash matches stored file
    r = client.get(f"{API}/captures/{sess['id']}/pcap", headers=admin_h)
    assert r.status_code == 200
    stored = app.state.core.storage.pcap_path(sess["id"]).read_bytes()
    assert hashlib.sha256(r.content).hexdigest() == hashlib.sha256(stored).hexdigest()
    assert len(rdpcap(str(app.state.core.storage.pcap_path(sess["id"])))) == sess["packets"]


def test_packet_limit_respected(client, admin_h, app):
    start_replay(client, admin_h, max_packets=50)
    st = wait_idle(client, admin_h)
    assert st["session"]["packets"] == 50 and st["session"]["stop_reason"] == "packet limit"
    assert len(rdpcap(str(app.state.core.storage.pcap_path(st["session"]["id"])))) == 50


def test_duration_limit_respected(client, admin_h):
    start_replay(client, admin_h, replay_speed=1, duration_s=1)
    t0 = time.time()
    st = wait_idle(client, admin_h)
    assert st["session"]["stop_reason"] == "duration limit"
    assert time.time() - t0 < 2.5


def test_manual_stop_and_conflict(client, admin_h):
    st = start_replay(client, admin_h, replay_speed=1)
    sid = st["session"]["id"]
    assert (
        client.post(
            f"{API}/captures", json={"source": "demo_all.pcap"}, headers=admin_h
        ).status_code
        == 409
    )
    r = client.post(f"{API}/captures/{sid}/stop", headers=admin_h)
    assert r.status_code == 200 and r.json()["state"] == "IDLE"
    assert (
        client.post(f"{API}/captures/{sid}/stop", headers=admin_h).status_code == 409
    )  # already stopped


def test_live_capture_needs_authorisation(client, admin_h):
    r = client.post(
        f"{API}/captures", json={"source_type": "live", "source": "eth0"}, headers=admin_h
    )
    assert r.status_code == 412 and r.json()["error"]["code"] == "AUTHORISATION_REQUIRED"


def test_bpf_rejected_for_replay(client, admin_h):
    r = client.post(
        f"{API}/captures", json={"source": "demo_all.pcap", "bpf": "tcp"}, headers=admin_h
    )
    assert r.status_code == 400 and r.json()["error"]["code"] == "BPF_LIVE_ONLY"


def test_session_search_with_display_filter(client, admin_h):
    start_replay(client, admin_h)
    sid = wait_idle(client, admin_h)["session"]["id"]
    r = client.get(
        f"{API}/captures/{sid}/packets",
        params={"filter": "arp and eth.src == 02:50:00:00:00:66"},
        headers=admin_h,
    ).json()
    assert r["matched"] == 6 and all(p["protocol"] == "ARP" for p in r["packets"])
    bad = client.get(
        f"{API}/captures/{sid}/packets", params={"filter": "ip.src =="}, headers=admin_h
    )
    assert bad.status_code == 400 and bad.json()["error"]["code"] == "FILTER_INVALID"


def test_replay_upload_rejects_non_pcap(client, admin_h):
    r = client.post(f"{API}/replay-files", files={"file": ("x.txt", b"hi")}, headers=admin_h)
    assert r.status_code == 400


def test_websocket_streams_packets_and_alerts(client, admin_h):
    token = admin_h["authorization"].split()[1]
    with client.websocket_connect(f"{API}/ws/live?token={token}&filter=arp") as ws:
        start_replay(client, admin_h, name="arp_spoof.pcap")
        got_pkts, alerts = [], []
        end = time.time() + 10
        while time.time() < end and not (alerts and got_pkts):
            msg = ws.receive_json()
            if msg["type"] == "batch":
                got_pkts += msg["packets"]
                alerts += [e["data"] for e in msg["events"] if e["topic"] == "alert"]
        assert got_pkts and all(p["protocol"] == "ARP" for p in got_pkts)  # server-side live filter
        assert alerts and alerts[0]["type"] == "ARP_SPOOF"


def test_websocket_rejects_bad_token(client):
    with client.websocket_connect(f"{API}/ws/live?token=bogus") as ws:
        msg = ws.receive_json()
        assert msg["type"] == "error" and msg["code"] == "UNAUTHENTICATED"


def test_capture_endpoints_require_auth(client):
    for path in ("/captures", "/capture/status", "/replay-files", "/interfaces"):
        assert client.get(API + path).status_code == 401


def test_unknown_or_malformed_session_id_is_404(client, admin_h):
    for sid in ("s_19990101_000000", "..%2F..%2Fsecret", "bad id"):
        r = client.get(f"{API}/captures/{sid}/pcap", headers=admin_h)
        assert r.status_code == 404, (sid, r.text)
        r = client.delete(f"{API}/captures/{sid}", headers=admin_h)
        assert r.status_code == 404, (sid, r.text)


def test_interfaces_endpoint_returns_dashboard_fields(client, admin_h):
    r = client.get(f"{API}/interfaces", headers=admin_h)
    assert r.status_code == 200
    for i in r.json():  # fields live.js reads, plus the capture modes from PR 08
        assert {"name", "description", "ips", "modes"} <= i.keys()
        assert isinstance(i["ips"], list)


def test_root_without_dashboard_is_404_not_500(client):
    r = client.get("/")
    assert r.status_code in (200, 404)  # 200 once PR 13 adds the dashboard
    if r.status_code == 404:
        assert r.json()["error"]["code"] == "NO_DASHBOARD"

"""TC-Sto-03 / TC-Filt-04 / TC-Sec-05: rotation, presets, audit log tamper evidence."""

import pytest

from pps.settings import DEFAULT_CONFIG
from pps.storage import INTERRUPTED_ERROR, Storage


def open_store(tmp_path, **kwargs):
    return Storage(tmp_path / "t.db", tmp_path / "caps", **kwargs)


@pytest.fixture
def store(tmp_path):
    s = open_store(tmp_path)
    yield s
    s.close()


def add_finished(s, sid, size, started):
    s.create_session(sid, "replay:x", "", "u")
    if size:
        s.pcap_path(sid).write_bytes(b"x" * size)
    s.finish_session(sid, 1, size)
    s._exec("UPDATE sessions SET started=? WHERE id=?", (started, sid))


# ---------------------------------------------------------------- rotation (PPS-F-032)
def test_rotation_deletes_oldest_first(store):
    for i in range(4):
        add_finished(store, f"s{i}", 1000, 1000 + i)
    removed = store.rotate(max_bytes=2500)
    assert removed == ["s0", "s1"]
    assert [x["id"] for x in store.list_sessions()] == ["s3", "s2"]
    assert not store.pcap_path("s0").exists()


def test_rotation_noop_when_under_limit(store):
    add_finished(store, "a", 100, 1)
    assert store.rotate(max_bytes=1000) == []


def test_rotation_never_removes_active_session(store):
    store.create_session("live", "live:eth0", "", "u")
    store.pcap_path("live").write_bytes(b"x" * 5000)
    assert store.rotate(max_bytes=10) == []


def test_rotation_respects_keep(store):
    for i in range(3):
        add_finished(store, f"s{i}", 1000, 1000 + i)
    assert store.rotate(max_bytes=1500, keep={"s0"}) == ["s1", "s2"]
    assert [x["id"] for x in store.list_sessions()] == ["s0"]


def test_rotation_skips_sessions_without_files(store):
    add_finished(store, "nofile", 0, 1)  # e.g. a failed capture that never wrote a PCAP
    add_finished(store, "a", 1000, 2)
    add_finished(store, "b", 1000, 3)
    assert store.rotate(max_bytes=1500) == ["a"]
    assert {x["id"] for x in store.list_sessions()} == {"nofile", "b"}


def test_rotation_deletes_nothing_when_limit_unreachable(store):
    # An untracked .pcap takes up more than the limit on its own; deleting
    # every session would not help, so history must be kept.
    (store.captures_dir / "untracked.pcap").write_bytes(b"x" * 5000)
    for i in range(3):
        add_finished(store, f"s{i}", 100, 1000 + i)
    assert store.rotate(max_bytes=1000) == []
    assert len(store.list_sessions()) == 3


def test_rotation_deletes_nothing_when_live_capture_exceeds_limit(store):
    store.create_session("live", "live:eth0", "", "u")
    store.pcap_path("live").write_bytes(b"x" * 5000)
    add_finished(store, "old", 100, 1)
    assert store.rotate(max_bytes=1000) == []
    assert store.get_session("old") is not None


# ---------------------------------------------------------------- crash recovery
def test_active_sessions_marked_interrupted_on_reopen(tmp_path):
    s = open_store(tmp_path)
    s.create_session("live", "live:eth0", "", "u")
    s.pcap_path("live").write_bytes(b"x" * 5000)
    s.close()  # simulates a crash: finish_session never ran

    with open_store(tmp_path) as s2:
        row = s2.get_session("live")
        assert row["status"] == "INTERRUPTED"
        assert row["ended"] is not None
        assert row["error"] == INTERRUPTED_ERROR
        assert s2.rotate(max_bytes=10) == ["live"]  # now reclaimable


def test_recovery_can_be_disabled(tmp_path):
    s = open_store(tmp_path)
    s.create_session("live", "live:eth0", "", "u")
    s.close()
    with open_store(tmp_path, recover_interrupted=False) as s2:
        assert s2.get_session("live")["status"] == "ACTIVE"


# ---------------------------------------------------------------- session ids
@pytest.mark.parametrize("bad", ["../../etc/x", "a/b", "a\\b", "..", "", "x" * 65, "a b"])
def test_invalid_session_ids_rejected(store, bad):
    with pytest.raises(ValueError):
        store.pcap_path(bad)
    with pytest.raises(ValueError):
        store.create_session(bad, "r", "", "u")


def test_pcap_path_stays_in_captures_dir(store):
    p = store.pcap_path("2026-11-04_abc-123")
    assert p.parent == store.captures_dir
    assert p.name == "2026-11-04_abc-123.pcap"


# ---------------------------------------------------------------- warning (PPS-F-034)
def test_storage_warning_threshold(store):
    store.create_session("a", "r", "", "u")
    store.pcap_path("a").write_bytes(b"x" * (950 * 1024))
    st = store.storage_status({"max_storage_mb": 1, "low_space_warn_pct": 0.001})
    assert st["quota_left_pct"] < 10
    st = store.storage_status({"max_storage_mb": 1, "low_space_warn_pct": 50})
    assert st["warning"] is True


# ---------------------------------------------------------------- config (PPS-F-060)
def test_config_defaults_and_update(store):
    assert store.get_config() == DEFAULT_CONFIG
    assert store.set_config({"max_storage_mb": 64})["max_storage_mb"] == 64
    assert store.get_config()["max_duration_s"] == DEFAULT_CONFIG["max_duration_s"]


def test_config_uses_given_defaults(tmp_path):
    with open_store(tmp_path, defaults={"max_storage_mb": 7, "low_space_warn_pct": 1}) as s:
        assert s.get_config() == {"max_storage_mb": 7, "low_space_warn_pct": 1}
        with pytest.raises(KeyError):
            s.set_config({"max_packets": 10})


def test_config_rejects_unknown_key_without_partial_write(store):
    with pytest.raises(KeyError):
        store.set_config({"max_storage_mb": 1, "nope": 1})
    assert store.get_config()["max_storage_mb"] == DEFAULT_CONFIG["max_storage_mb"]


# ---------------------------------------------------------------- alerts (PPS-F-043)
def test_alerts_save_filter_and_ack(store):
    a1 = store.save_alert("s1", {"type": "ARP_SPOOF", "severity": "high", "ts": 10.0,
                                 "message": "m1", "details": {"ip": "10.0.0.1"}})
    store.save_alert("s2", {"type": "PORT_SCAN", "severity": "medium", "ts": 20.0,
                            "message": "m2"})
    assert [a["type"] for a in store.list_alerts()] == ["PORT_SCAN", "ARP_SPOOF"]
    assert [a["id"] for a in store.list_alerts(type_="ARP_SPOOF")] == [a1]
    assert [a["message"] for a in store.list_alerts(since=15.0)] == ["m2"]
    assert [a["message"] for a in store.list_alerts(session_id="s1")] == ["m1"]
    assert store.list_alerts(session_id="s1")[0]["details"] == {"ip": "10.0.0.1"}
    assert store.ack_alert(a1) is True
    assert store.list_alerts(type_="ARP_SPOOF")[0]["acked"] is True
    assert store.ack_alert(9999) is False


# ---------------------------------------------------------------- presets (PPS-F-023)
def test_presets_persist(tmp_path):
    s = open_store(tmp_path)
    s.save_preset("web", "http or tcp.port == 443", "a")
    s.close()
    with open_store(tmp_path) as s2:
        assert s2.list_presets()[0]["expression"] == "http or tcp.port == 443"
        assert s2.delete_preset("web") and s2.list_presets() == []


# ---------------------------------------------------------------- users (PPS-F-061)
def test_upsert_user_keeps_hash_when_none(store):
    store.upsert_user("alice", "hash1", "viewer")
    store.upsert_user("alice", None, "admin", active=False)
    u = store.get_user("alice")
    assert (u["pw_hash"], u["role"], u["active"]) == ("hash1", "admin", 0)
    assert store.user_count() == 1
    assert "pw_hash" not in store.list_users()[0]


# ---------------------------------------------------------------- audit log (PPS-SR-005)
def test_audit_chain_detects_tampering(store):
    for i in range(5):
        store.audit("admin", "CONFIG_CHANGED", {"i": i})
    v = store.verify_audit()
    assert (v["ok"], v["entries"], v["broken_at"]) == (True, 5, None)
    store._exec("UPDATE audit_log SET details=? WHERE id=3", ('{"i": 99}',))
    v = store.verify_audit()
    assert v["ok"] is False and v["broken_at"] == 3


def test_audit_chain_detects_deleted_entry(store):
    for i in range(4):
        store.audit("a", "X", {"i": i})
    store._exec("DELETE FROM audit_log WHERE id=2")
    assert store.verify_audit()["ok"] is False


def test_audit_tail_deletion_needs_external_head(store):
    head = None
    for i in range(3):
        head = store.audit("a", "X", {"i": i})
    assert store.verify_audit(expected_head=head)["ok"] is True
    store._exec("DELETE FROM audit_log WHERE id=3")
    assert store.verify_audit()["ok"] is True  # chain alone cannot see a truncated tail
    v = store.verify_audit(expected_head=head)
    assert v["ok"] is False and v["broken_at"] == "head"


def test_audit_hmac_key_required_to_verify(tmp_path):
    s = open_store(tmp_path, audit_key=b"device-secret")
    for i in range(3):
        s.audit("a", "X", {"i": i})
    assert s.verify_audit()["ok"] is True
    s.close()
    with open_store(tmp_path) as unkeyed:  # without the key the chain does not verify
        assert unkeyed.verify_audit()["ok"] is False
    with open_store(tmp_path, audit_key=b"wrong") as wrong:
        assert wrong.verify_audit()["ok"] is False

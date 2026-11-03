"""TC-Sto-03 / TC-Filt-04 / TC-Sec-05: rotation, presets, audit log tamper evidence."""

import time

from pps.storage import Storage


def make(tmp_path):
    return Storage(tmp_path / "t.db", tmp_path / "caps")


def test_rotation_deletes_oldest_first(tmp_path):
    s = make(tmp_path)
    for i in range(4):
        sid = f"s{i}"
        s.create_session(sid, "replay:x", "", "u")
        s.pcap_path(sid).write_bytes(b"x" * 1000)
        s.finish_session(sid, 1, 1000)
        s._exec("UPDATE sessions SET started=? WHERE id=?", (1000 + i, sid))
    removed = s.rotate(max_bytes=2500)
    assert removed == ["s0", "s1"]
    assert [x["id"] for x in s.list_sessions()] == ["s3", "s2"]


def test_rotation_never_removes_active_session(tmp_path):
    s = make(tmp_path)
    s.create_session("live", "live:eth0", "", "u")
    s.pcap_path("live").write_bytes(b"x" * 5000)
    assert s.rotate(max_bytes=10) == []


def test_storage_warning_threshold(tmp_path):
    s = make(tmp_path)
    s.create_session("a", "r", "", "u")
    s.pcap_path("a").write_bytes(b"x" * (950 * 1024))
    st = s.storage_status({"max_storage_mb": 1, "low_space_warn_pct": 0.001})
    assert st["quota_left_pct"] < 10
    st = s.storage_status({"max_storage_mb": 1, "low_space_warn_pct": 50})
    assert st["warning"] is True


def test_presets_persist(tmp_path):
    s = make(tmp_path)
    s.save_preset("web", "http or tcp.port == 443", "a")
    s.close()
    s2 = make(tmp_path)
    assert s2.list_presets()[0]["expression"] == "http or tcp.port == 443"
    assert s2.delete_preset("web") and s2.list_presets() == []


def test_audit_chain_detects_tampering(tmp_path):
    s = make(tmp_path)
    for i in range(5):
        s.audit("admin", "CONFIG_CHANGED", {"i": i})
        time.sleep(0.001)
    assert s.verify_audit() == {"ok": True, "entries": 5, "broken_at": None}
    s._exec("UPDATE audit_log SET details=? WHERE id=3", ('{"i": 99}',))
    v = s.verify_audit()
    assert v["ok"] is False and v["broken_at"] == 3


def test_audit_chain_detects_deleted_entry(tmp_path):
    s = make(tmp_path)
    for i in range(4):
        s.audit("a", "X", {"i": i})
    s._exec("DELETE FROM audit_log WHERE id=2")
    assert s.verify_audit()["ok"] is False

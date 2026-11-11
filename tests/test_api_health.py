"""TC-Cfg-03 via the API: device health view."""

from .conftest import API


def test_health_view(client, admin_h):
    h = client.get(f"{API}/device/health", headers=admin_h).json()
    assert {"battery", "storage", "uptime_s", "cpu_percent"} <= set(h)
    assert h["storage"]["quota_bytes"] == 500 * 1024 * 1024

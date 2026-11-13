
"""Tests for the PPS-F-062 device health API."""

from .conftest import API


def test_health_view(client, admin_h):
    response = client.get(
        f"{API}/device/health",
        headers=admin_h,
    )

    assert response.status_code == 200

    health = response.json()

    assert {
        "battery",
        "storage",
        "uptime_s",
        "cpu_percent",
    } <= set(health)

    assert health["storage"]["quota_bytes"] == 500 * 1024 * 1024


def test_health_requires_authentication(client):
    response = client.get(f"{API}/device/health")

    assert response.status_code == 401


def test_trainee_can_read_health(client, role_headers):
    response = client.get(
        f"{API}/device/health",
        headers=role_headers["trainee"],
    )

    assert response.status_code == 200
    assert "battery" in response.json()


def test_health_without_battery(client, admin_h, monkeypatch):
    from pps import health as health_module

    monkeypatch.setattr(
        health_module.psutil,
        "sensors_battery",
        lambda: None,
    )

    response = client.get(
        f"{API}/device/health",
        headers=admin_h,
    )

    assert response.status_code == 200
    assert response.json()["battery"] is None


def test_health_reports_low_storage(client, admin_h, app, monkeypatch):
    monkeypatch.setattr(
        app.state.core.storage,
        "storage_status",
        lambda config: {
            "used_bytes": 480 * 1024 * 1024,
            "quota_bytes": 500 * 1024 * 1024,
            "disk_free_pct": 10,
            "warning": True,
        },
    )

    response = client.get(
        f"{API}/device/health",
        headers=admin_h,
    )

    assert response.status_code == 200
    assert response.json()["storage"]["warning"] is True

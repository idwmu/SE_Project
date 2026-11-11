"""TC-Cfg-01 via the API: configuration read/update and validation."""

from .conftest import API


def test_config_read_and_update(client, role_headers):
    t, ad = role_headers["trainee"], role_headers["admin"]
    assert client.get(f"{API}/config", headers=t).json()["portscan_threshold"] == 20
    assert (
        client.put(f"{API}/config", json={"portscan_threshold": 25}, headers=t).status_code == 403
    )
    r = client.put(
        f"{API}/config",
        json={"portscan_threshold": 25, "arp_whitelist": ["192.168.50.1=02:50:00:00:00:66"]},
        headers=ad,
    )
    assert r.status_code == 200 and r.json()["portscan_threshold"] == 25
    assert client.get(f"{API}/config", headers=t).json()["arp_whitelist"] == [
        "192.168.50.1=02:50:00:00:00:66"
    ]


def test_config_validation(client, admin_h):
    for body in (
        {"portscan_threshold": 1},
        {"nope": 1},
        {"arp_whitelist": ["bad"]},
        {"max_storage_mb": "x"},
        {"portscan_threshold": 25.5},  # would silently become 25
        {"portscan_threshold": True},  # bool is an int subclass
    ):
        r = client.put(f"{API}/config", json=body, headers=admin_h)
        assert r.status_code == 400, body
        assert r.json()["error"]["code"] in ("BAD_VALUE", "BAD_KEY")


def test_config_requires_auth(client):
    assert client.get(f"{API}/config").status_code == 401

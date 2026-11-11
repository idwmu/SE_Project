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

def test_arp_whitelist_entries_are_validated(client, admin_h):
    bad = [
        "=",
        "192.168.1.1=",
        "=02:50:00:00:00:66",
        "invalid=invalid",
        "192.168.1.256=02:50:00:00:00:66",  # octet out of range
        "fe80::1=02:50:00:00:00:66",  # IPv6: the detector tracks IPv4 ARP only
        "192.168.1.1=02:50:00:00:00",  # five octets
        "192.168.1.1=02:50:00:00:00:6g",  # not hex
        "192.168.1.1=02:50-00:00:00:66",  # mixed separators
        "192.168.1.1",  # no "="
        5,
    ]
    for entry in bad:
        r = client.put(f"{API}/config", json={"arp_whitelist": [entry]}, headers=admin_h)
        assert r.status_code == 400, entry
        assert r.json()["error"]["code"] == "BAD_VALUE"
    r = client.put(f"{API}/config", json={"arp_whitelist": "x=y"}, headers=admin_h)
    assert r.status_code == 400


def test_arp_whitelist_is_stored_in_the_form_the_detector_compares(client, admin_h):
    r = client.put(
        f"{API}/config",
        json={"arp_whitelist": [" 192.168.50.1 = 02-50-00-00-00-AA "]},
        headers=admin_h,
    )
    assert r.status_code == 200
    assert r.json()["arp_whitelist"] == ["192.168.50.1=02:50:00:00:00:aa"]

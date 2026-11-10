"""TC-Filt-04 via the API: presets."""

from .conftest import API


def test_presets_crud(client, role_headers):
    a = role_headers["analyst"]
    assert (
        client.put(
            f"{API}/filters/presets/web", json={"expression": "http or tcp.port == 443"}, headers=a
        ).status_code
        == 200
    )
    assert (
        client.put(f"{API}/filters/presets/bad", json={"expression": "(("}, headers=a).status_code
        == 400
    )
    assert [p["name"] for p in client.get(f"{API}/filters/presets", headers=a).json()] == ["web"]
    assert client.delete(f"{API}/filters/presets/web", headers=a).status_code == 200


def test_validate_endpoint(client, role_headers):
    t = role_headers["trainee"]
    ok = client.post(
        f"{API}/filters/validate", json={"expression": "dns or http"}, headers=t
    ).json()
    bad = client.post(
        f"{API}/filters/validate", json={"expression": "ip.src == x"}, headers=t
    ).json()
    assert ok == {"valid": True, "checked": True}
    assert bad["valid"] is False and "not an IP" in bad["error"]
    bpf = client.post(
        f"{API}/filters/validate", json={"expression": "tcp port 80", "kind": "bpf"}, headers=t
    ).json()
    assert bpf["valid"] is True  # checked=False where libpcap is not installed

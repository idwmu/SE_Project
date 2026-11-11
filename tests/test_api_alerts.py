"""TC-Anom-04 via the API: alerts stored, listed, filtered and acknowledged."""

from .conftest import API, start_replay, wait_idle


def test_alerts_listed_filtered_and_acked(client, role_headers):
    a, t = role_headers["analyst"], role_headers["trainee"]
    start_replay(client, a)
    wait_idle(client, a)
    alerts = client.get(f"{API}/alerts", headers=t).json()
    assert sorted(x["type"] for x in alerts) == ["ARP_SPOOF", "PORT_SCAN"]
    assert all(x["session_id"] and x["ts"] for x in alerts)
    only = client.get(f"{API}/alerts", params={"type": "PORT_SCAN"}, headers=t).json()
    assert [x["type"] for x in only] == ["PORT_SCAN"]
    aid = only[0]["id"]
    assert (
        client.post(f"{API}/alerts/{aid}/ack", headers=t).status_code == 403
    )  # trainee cannot ack
    assert client.post(f"{API}/alerts/{aid}/ack", headers=a).status_code == 200
    assert (
        client.get(f"{API}/alerts", params={"type": "PORT_SCAN"}, headers=a).json()[0]["acked"]
        is True
    )
    assert client.post(f"{API}/alerts/99999/ack", headers=a).status_code == 404


def test_alerts_require_auth(client):
    assert client.get(f"{API}/alerts").status_code == 401


def test_alerts_limit_validated(client, role_headers):
    a = role_headers["analyst"]
    for bad in (-1, 0, 1001):  # a negative LIMIT would make SQLite return every row
        assert client.get(f"{API}/alerts", params={"limit": bad}, headers=a).status_code == 422, bad
    assert client.get(f"{API}/alerts", params={"limit": 1}, headers=a).status_code == 200

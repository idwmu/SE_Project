"""TC-Sec-01 / TC-Sec-04 / TC-App-01 via the API: pairing, login, lockout, roles."""

from .conftest import API, PIN, login, pair


def test_wrong_pin_rejected_and_lockout(client):
    for _ in range(5):
        assert client.post(f"{API}/pair", json={"pin": "000000"}).status_code == 401
    r = client.post(f"{API}/pair", json={"pin": PIN})
    assert r.status_code == 429 and r.json()["error"]["code"] == "LOCKED_OUT"
    assert int(r.headers["retry-after"]) > 0


def test_login_requires_pairing(client, app):
    r = client.post(
        f"{API}/auth/login", json={"username": "admin", "password": app.state.admin_password}
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "NOT_PAIRED"


def test_demotion_applies_immediately(client, role_headers):
    ad, a = role_headers["admin"], role_headers["analyst"]
    assert client.get(f"{API}/interfaces", headers=a).status_code == 200
    client.patch(f"{API}/users/analyst1", json={"role": "trainee"}, headers=ad)
    assert client.get(f"{API}/interfaces", headers=a).status_code == 403
    client.patch(f"{API}/users/analyst1", json={"active": False}, headers=ad)
    assert client.get(f"{API}/captures", headers=a).status_code == 401


def test_pairing_via_api_returns_token(client):
    assert pair(client)


def test_error_codes_from_auth_module(client, app, admin_h):
    r = client.post(f"{API}/pair", json={"pin": "000000"})
    assert r.status_code == 401 and r.json()["error"]["code"] == "PIN_INVALID"
    r = client.post(
        f"{API}/auth/login",
        json={"username": "admin", "password": "wrong-password"},
        headers={"x-pps-client": pair(client)},
    )
    assert r.status_code == 401 and r.json()["error"]["code"] == "INVALID_CREDENTIALS"
    r = client.patch(f"{API}/users/admin", json={"role": "analyst"}, headers=admin_h)
    assert r.status_code == 409 and r.json()["error"]["code"] == "LAST_ADMIN"
    r = client.patch(f"{API}/users/admin", json={}, headers=admin_h)
    assert r.status_code == 400
    r = client.patch(f"{API}/users/nobody", json={"active": False}, headers=admin_h)
    assert r.status_code == 404 and r.json()["error"]["code"] == "NOT_FOUND"


def test_me_and_password_reset(client, role_headers):
    ad = role_headers["admin"]
    assert client.get(f"{API}/auth/me", headers=role_headers["trainee"]).json() == {
        "username": "trainee1",
        "role": "trainee",
    }
    r = client.patch(f"{API}/users/trainee1", json={"password": "new-secret-pw"}, headers=ad)
    assert r.status_code == 200
    # the reset revokes the old session; the new password works
    assert client.get(f"{API}/auth/me", headers=role_headers["trainee"]).status_code == 401
    assert login(client, "trainee1", "new-secret-pw")
